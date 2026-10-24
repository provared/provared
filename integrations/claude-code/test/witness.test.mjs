// The witness for seals, run as a service (witness.mjs): it signs for a seal
// only where the seal extends the one it holds, keeps each statement in its
// journal and its state on the disk before it answers, and signs nothing
// after a restart until its operator says it is up to date. Every witness
// here works in a temporary folder and on a free port.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import nodeCrypto from 'node:crypto';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { bookIdentity, checkBook, entryLine, fingerprint, fromBase64url, generateSealKeySet, keySetFingerprint, openRecorder, thumbprint, toBase64url, utf8, witnessProof, writeSeal } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { WITNESS_LABELS, WITNESS_MAX_BODY, WITNESS_MAX_WAITING, initWitness, readSettings, readToken, startWitness, updateFrom, witnessClient, witnessFiles } = await import('../witness.mjs');
const { feedHmac } = await import('../feed.mjs');
const { makeAgentKeys } = await import('../recorder.mjs');
const { freePort, refusedStart, signSlip, tempFolder } = await import('./world.mjs');

const witnessFile = fileURLToPath(new URL('../witness.mjs', import.meta.url));
const lineCount = (text) => text.split('\n').filter(Boolean).length;
const firstOf = (text) => text.split('\n')[0];
const journalOf = (folder) => readFileSync(witnessFiles(folder).journal, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const stateOf = (folder) => JSON.parse(readFileSync(witnessFiles(folder).state, 'utf8'));

/**
 * A recorder's book made with the library (an agent, a passkey, a slip and
 * stubs), the recorder's keys to seal it, and a witness made for it.
 */
async function setting({ recorders } = {}) {
  const folder = tempFolder('provared-wt-');
  const agent = await makeAgentKeys(folder);
  const passkey = await developmentPasskey();
  const slip = await signSlip({ agentKeys: agent.keys, passkey });
  const slipFingerprint = await fingerprint(fromBase64url(slip.payload));
  const recorder = await generateSealKeySet();
  const by = { keys: recorder.keys, name: 'A recorder (test)' };
  const sealer = await keySetFingerprint(recorder.keys);
  const issuer = await thumbprint(passkey.key);
  let calls = 0;
  /** A stub writer on a book: a new one, or one that goes on from the text given. */
  const book = async (text = `${entryLine({ slip })}\n`) => {
    const w = await openRecorder({ book: text, slip: slipFingerprint, privateKeys: agent.privateKeys, issuerKeys: [issuer] });
    w.more = async (n = 1) => {
      for (let i = 0; i < n; i++) await w.record({ action: 'provared.code.read', details: [{ name: 'Read', sha256: await fingerprint(utf8(`call ${++calls}`)) }] });
      return w.book();
    };
    return w;
  };
  const seal = (text, fields = {}) => writeSeal(text, { by, ...fields }, recorder.privateKeys);
  const wfolder = tempFolder('provared-w-');
  const made = await initWitness({ folder: wfolder, recorders: recorders ?? [sealer] });
  return { folder, agent, passkey, slip, recorder, by, sealer, issuer, book, seal, wfolder, made };
}

const clientOf = (s, w, role = 'recorder') => witnessClient({ address: `http://127.0.0.1:${w.port}`, token: readToken(role === 'recorder' ? witnessFiles(s.wfolder).token : witnessFiles(s.wfolder).operator), role });
/** Ask a witness to sign for a seal of a book (the book as it was before the seal), with the right proof for what it holds. */
async function ask(client, text, sealed, held = null) {
  return client.ask('POST', '/witness', { entry: { seal: sealed.record }, proof: (await witnessProof(text, lineCount(text), held)).map(toBase64url), first: firstOf(text) });
}

test('init makes the keys, both tokens and an empty journal; run again it keeps them and adds the recorders named; a journal with no keys is refused', async () => {
  const folder = tempFolder('provared-w-');
  const fp = 'A'.repeat(43);
  const made = await initWitness({ folder, name: 'Sam\'s witness', recorders: [fp] });
  assert.equal(made.made, true);
  const f = witnessFiles(folder);
  for (const file of [f.keys, f.token, f.operator, f.journal, f.settings]) assert.ok(existsSync(file), file);
  assert.equal(readFileSync(f.journal, 'utf8'), '', 'the journal is empty');
  assert.notEqual(readToken(f.token), readToken(f.operator), 'two tokens');
  const again = await initWitness({ folder, recorders: ['B'.repeat(42) + 'A'] });
  assert.equal(again.made, false);
  assert.equal(again.fingerprint, made.fingerprint, 'the same keys');
  assert.deepEqual(readSettings(folder).recorders, [fp, 'B'.repeat(42) + 'A']);
  assert.equal(readSettings(folder).name, 'Sam\'s witness');
  // A journal without keys: new keys would be another witness with the old one's journal.
  const other = tempFolder('provared-w-');
  writeFileSync(join(other, 'journal.jsonl'), '');
  const allFiles = /witness-keys\.jwk, journal\.jsonl, state\.json, checkpoint\.json and journal-mark\.json/;
  await assert.rejects(initWitness({ folder: other, recorders: [fp] }), (e) => /journal\.jsonl is there, but the witness's keys are not/.test(e.message) && allFiles.test(e.message));
  // A state, a checkpoint or a journal mark without keys, the journal moved out alone: refused too, naming each.
  for (const [file, words] of [['state.json', /^state\.json is there/], ['checkpoint.json', /^checkpoint\.json is there/], ['journal-mark.json', /^journal-mark\.json is there/]]) {
    const lone = tempFolder('provared-w-');
    writeFileSync(join(lone, file), '{}');
    await assert.rejects(initWitness({ folder: lone, recorders: [fp] }), (e) => words.test(e.message) && allFiles.test(e.message), file);
    assert.ok(!existsSync(join(lone, 'witness-keys.jwk')), 'no keys made');
  }
  // Keys without a journal: the start names every file to move out together, to start a new witness.
  const keysOnly = tempFolder('provared-w-');
  await initWitness({ folder: keysOnly, recorders: [fp] });
  renameSync(witnessFiles(keysOnly).journal, `${witnessFiles(keysOnly).journal}.aside`);
  await refusedStart(startWitness, { folder: keysOnly, port: 0 }, /its journal .* is not\.[\s\S]*witness-keys\.jwk, journal\.jsonl, state\.json, checkpoint\.json and journal-mark\.json/);
  await assert.rejects(initWitness({ folder: tempFolder('provared-w-'), recorders: ['not a fingerprint'] }), /not the fingerprint/);
  // A witness that serves no recorder does not start.
  const none = tempFolder('provared-w-');
  await initWitness({ folder: none });
  await refusedStart(startWitness, { folder: none, port: 0 }, /serves no recorder/);
});

test('a witness signs for a first seal and for one that extends it; each statement is in its journal and its state, on the disk, before it is given out', async () => {
  const s = await setting();
  const seen = [];
  const w = await startWitness({
    folder: s.wfolder,
    port: 0,
    ready: true,
    // At the last step before the answer: what the disk holds then.
    faults: (step) => {
      if (step === 'saved') seen.push({ journal: journalOf(s.wfolder).length, state: stateOf(s.wfolder) });
    },
  });
  try {
    const client = clientOf(s, w);
    const writer = await s.book();
    const t1 = await writer.more(1);
    const s1 = await s.seal(t1);
    const r1 = await ask(client, t1, s1);
    assert.equal(r1.code, 200, JSON.stringify(r1.body));
    assert.equal(seen.length, 1);
    assert.equal(seen[0].journal, 1, 'the journal line was on the disk before the answer');
    assert.equal(seen[0].state.journal, 1);
    assert.equal(seen[0].state.witness.books[0].seal.payload, s1.record.payload, 'and the state holds the seal');
    assert.deepEqual(journalOf(s.wfolder)[0].entry.witnesses, [r1.body.statement], 'the journal holds the statement given out');

    await writer.add({ seal: s1.record, witnesses: [r1.body.statement] });
    const t2 = await writer.more(2);
    const s2 = await s.seal(t2, { previous: s1.fingerprint });
    const r2 = await ask(client, t2, s2, 2);
    assert.equal(r2.code, 200, JSON.stringify(r2.body));
    assert.equal(journalOf(s.wfolder).length, 2);
    await writer.add({ seal: s2.record, witnesses: [r2.body.statement] });

    // The library's checker counts both, for a person who names the passkey, the recorder and the witness.
    const result = await checkBook(writer.book(), { issuerKeys: [s.issuer], sealKeys: [s.sealer], witnesses: [s.made.fingerprint] });
    assert.equal(result.summary.intact, true);
    assert.deepEqual(result.summary.witnessed, { seal: 5, entries: 5, by: [s.made.fingerprint], seals: [2, 5] });

    // The same seal again: the same statement, and no new journal line.
    assert.deepEqual((await ask(client, t2, s2, 2)).body.statement, r2.body.statement);
    assert.equal(journalOf(s.wfolder).length, 2);

    // What it holds, for its operator.
    const status = (await clientOf(s, w, 'operator').ask('GET', '/status')).body;
    assert.equal(status.ready, true);
    assert.equal(status.sequences.length, 1);
    assert.equal(status.sequences[0].sequence, await bookIdentity(s.recorder.keys, utf8(firstOf(t1))), 'named as the library names a sequence');
    assert.equal(status.sequences[0].entries, 5);
    assert.equal(status.journal.lines, 2);
  } finally {
    await w.close();
  }
});

test('a fork is refused: another seal at the size held, a seal that does not extend the one held, and a seal of an earlier book', async () => {
  const s = await setting();
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    const client = clientOf(s, w);
    const a = await s.book();
    const ta = await a.more(1);
    const sa = await s.seal(ta);
    assert.equal((await ask(client, ta, sa)).code, 200);
    // Another history from the same first line, sealed at the same size.
    const b = await s.book();
    const tb = await b.more(1);
    const sb = await s.seal(tb);
    const fork = await ask(client, tb, sb);
    assert.equal(fork.code, 409);
    assert.equal(fork.body.refused.code, 'seal-mismatch');
    // Another history, longer, that names the seal held and does not extend it.
    const tb2 = await b.more(1);
    const notExtending = await s.seal(tb2, { previous: sa.fingerprint });
    const r = await ask(client, tb2, notExtending, 2);
    assert.equal(r.code, 409);
    assert.equal(r.body.refused.code, 'proof-invalid');
    assert.equal(journalOf(s.wfolder).length, 1, 'nothing refused is in the journal');
    // The next book, which starts from the seal held: signed. Then a seal of the book before: refused.
    const next = await s.book();
    const tn = next.book();
    assert.equal((await ask(client, tn, await s.seal(tn, { book: 2, previous: sa.fingerprint }))).code, 200);
    await a.add({ seal: sa.record });
    const ta2 = await a.more(1);
    const earlier = await ask(client, ta2, await s.seal(ta2, { previous: sa.fingerprint }), 2);
    assert.equal(earlier.code, 409);
    assert.equal(earlier.body.refused.code, 'seal-mismatch');
  } finally {
    await w.close();
  }
});

test('started again from what it kept, it signs nothing until its operator says it is up to date; then the same seal gets the same statement', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const first = await ask(clientOf(s, w), t1, s1);
  await w.close();

  w = await startWitness({ folder: s.wfolder, port: 0 });
  try {
    const refused = await ask(clientOf(s, w), t1, s1);
    assert.equal(refused.code, 409);
    assert.equal(refused.body.refused.code, 'witness-not-ready');
    const op = (path, method = 'POST') => clientOf(s, w, 'operator').ask(method, path, method === 'POST' ? {} : undefined);
    assert.equal((await op('/status', 'GET')).body.ready, false);
    // A recorder's token does not say it.
    assert.equal((await clientOf(s, w).ask('POST', '/ready', {})).code, 403);
    assert.equal((await op('/ready')).code, 200);
    assert.deepEqual((await ask(clientOf(s, w), t1, s1)).body.statement, first.body.statement, 'the same statement');
    await writer.add({ seal: s1.record });
    const t2 = await writer.more(1);
    assert.equal((await ask(clientOf(s, w), t2, await s.seal(t2, { previous: s1.fingerprint }), 2)).code, 200);
  } finally {
    await w.close();
  }
  // Started with --ready, it signs at once, and says why.
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    const st = await w.status();
    assert.equal(st.ready, true);
    assert.match(st.notes.join(' '), /--ready/);
  } finally {
    await w.close();
  }
});

for (const step of ['journaled', 'saved']) {
  test(`a stop after "${step}", before the answer: no statement is given out, it signs nothing more, and after a restart it holds the seal and gives the statement it kept`, async () => {
    const s = await setting();
    const crash = new Error(`stopped after ${step}`);
    let w = await startWitness({ folder: s.wfolder, port: 0, ready: true, faults: (at) => { if (at === step) throw crash; } });
    const writer = await s.book();
    const t1 = await writer.more(1);
    const s1 = await s.seal(t1);
    try {
      const r = await ask(clientOf(s, w), t1, s1);
      assert.equal(r.code, 503);
      assert.equal(r.body.statement, undefined, 'no statement is given out');
      assert.equal(r.body.code, 'witness-stopped');
      assert.equal((await ask(clientOf(s, w), t1, s1)).code, 503, 'and it signs nothing more');
    } finally {
      await w.close();
    }
    const kept = journalOf(s.wfolder);
    assert.equal(kept.length, 1, 'the journal line is on the disk');
    const stateFile = witnessFiles(s.wfolder).state;
    if (step === 'saved') assert.equal(stateOf(s.wfolder).journal, 1, 'and the state');
    else assert.ok(!existsSync(stateFile) || stateOf(s.wfolder).journal === 0, 'and the state is the one before (a new witness keeps none until its first statement)');
    w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
    try {
      assert.equal((await w.status()).sequences[0].entries, 2, 'it holds the seal again');
      assert.equal(stateOf(s.wfolder).journal, 1, 'the state was brought up to the journal');
      assert.deepEqual((await ask(clientOf(s, w), t1, s1)).body.statement, kept[0].entry.witnesses[0], 'the statement it kept');
    } finally {
      await w.close();
    }
  });
}

test('a journal cut off in the middle of its last line is mended at the start; one changed elsewhere, shorter than the state, or missing, stops the start', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  await ask(clientOf(s, w), t1, await s.seal(t1));
  await w.close();
  const f = witnessFiles(s.wfolder);
  const whole = readFileSync(f.journal, 'utf8');
  const state = readFileSync(f.state, 'utf8');

  // A line cut off while it was written: taken off, and said so.
  writeFileSync(f.journal, `${whole}{"n":2,"kind":"witness","entry`);
  w = await startWitness({ folder: s.wfolder, port: 0 });
  assert.match((await w.status()).notes.join(' '), /had no line break/);
  await w.close();
  assert.equal(readFileSync(f.journal, 'utf8'), whole);

  // A line changed elsewhere.
  writeFileSync(f.journal, whole.replace('"kind":"witness"', '"kind":"other"'));
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /journal was changed/);
  // A state that reflects more lines than the journal holds.
  writeFileSync(f.journal, '');
  // (Its journal mark says so too; the state is looked at first.)
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /state\.json reflects 1 lines of the journal's segment 1, and the journal holds 0: lines were taken out of the journal/);
  // No journal at all.
  writeFileSync(f.journal, whole);
  writeFileSync(f.state, state);
  renameSync(f.journal, `${f.journal}.aside`);
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /its journal .* is not/);
  renameSync(`${f.journal}.aside`, f.journal);
  // A state that is lost: rebuilt from the journal.
  renameSync(f.state, `${f.state}.aside`);
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    assert.equal((await w.status()).sequences.length, 1, 'rebuilt from the journal');
  } finally {
    await w.close();
  }
});

test('a question needs the token, a conversation of its own, and the right role; too large, malformed or for a recorder not served, it is refused', async () => {
  const s = await setting();
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const address = `http://127.0.0.1:${w.port}`;
  try {
    // Without the token: the witness's proof does not check, and nothing is believed.
    await assert.rejects(witnessClient({ address, token: nodeCrypto.randomBytes(32).toString('base64url') }).ask('GET', '/about'), (e) => e.code === 'not-the-witness');
    // A question with no conversation.
    assert.equal((await fetch(`${address}/witness`, { method: 'POST', body: '{}' })).status, 401);
    // A conversation takes one question: the same question again is refused.
    const token = Buffer.from(readToken(witnessFiles(s.wfolder).token));
    const mine = nodeCrypto.randomBytes(32).toString('base64url');
    const hello = await (await fetch(`${address}/hello`, { headers: { 'Provared-Witness-Hello': mine, 'Provared-Witness-Role': 'recorder' } })).json();
    const key = feedHmac(token, WITNESS_LABELS.key, 'recorder', mine, hello.session);
    const proof = feedHmac(key, WITNESS_LABELS.question, 'GET /about', nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest('base64url')).toString('base64url');
    const headers = { 'Provared-Witness-Session': hello.session, 'Provared-Witness-Hello': mine, 'Provared-Witness-Role': 'recorder', 'Provared-Witness-Proof': proof };
    assert.equal((await fetch(`${address}/about`, { headers })).status, 200);
    const twice = await fetch(`${address}/about`, { headers });
    assert.equal(twice.status, 401);
    assert.match((await twice.json()).error, /takes one question/);
    // The same proof under the operator's role does not check.
    assert.equal((await fetch(`${address}/about`, { headers: { ...headers, 'Provared-Witness-Role': 'operator' } })).status, 401);
    // Anyone may have a hello; a question in it whose proof was made without the token, or for another question, is refused.
    for (const [key2, path] of [[nodeCrypto.randomBytes(32), '/about'], [null, '/latest?sequence=' + 'A'.repeat(43)]]) {
      const mine2 = nodeCrypto.randomBytes(32).toString('base64url');
      const hello2 = await (await fetch(`${address}/hello`, { headers: { 'Provared-Witness-Hello': mine2, 'Provared-Witness-Role': 'recorder' } })).json();
      const k = key2 ?? feedHmac(token, WITNESS_LABELS.key, 'recorder', mine2, hello2.session);
      const p = feedHmac(k, WITNESS_LABELS.question, 'GET /about', nodeCrypto.createHash('sha256').update(Buffer.alloc(0)).digest('base64url')).toString('base64url');
      const r = await fetch(`${address}${path}`, { headers: { 'Provared-Witness-Session': hello2.session, 'Provared-Witness-Hello': mine2, 'Provared-Witness-Role': 'recorder', 'Provared-Witness-Proof': p } });
      assert.equal(r.status, 401, path);
      assert.match((await r.json()).error, /does not carry the proof/);
    }
    // The operator's commands take the operator's token.
    const recorder = clientOf(s, w);
    for (const [method, path] of [['GET', '/status'], ['POST', '/ready'], ['POST', '/update'], ['POST', '/stop']]) {
      assert.equal((await recorder.ask(method, path, method === 'POST' ? {} : undefined)).code, 403, path);
    }
    // Methods and paths.
    assert.equal((await fetch(`${address}/witness`)).status, 405);
    assert.equal((await fetch(`${address}/nothing`)).status, 404);
    // Too large: refused before anything is read into the witness.
    const big = await fetch(`${address}/witness`, { method: 'POST', body: 'x'.repeat(WITNESS_MAX_BODY + 1) }).catch((e) => ({ status: e.cause?.code ?? 'closed' }));
    assert.ok(big.status === 413 || big.status === 'ECONNRESET' || big.status === 'EPIPE', String(big.status));
    // Malformed.
    assert.equal((await recorder.ask('POST', '/witness', { entry: {} })).code, 400);
    assert.equal((await recorder.ask('POST', '/witness', { entry: { seal: {} }, proof: [], first: 'x' })).code, 400);
    const writer = await s.book();
    const t1 = await writer.more(1);
    const s1 = await s.seal(t1);
    assert.equal((await recorder.ask('POST', '/witness', { entry: { seal: s1.record }, proof: ['short'], first: firstOf(t1) })).code, 400);
    assert.equal((await recorder.ask('POST', '/witness', { entry: { seal: s1.record, witnesses: [] }, proof: [], first: firstOf(t1) })).code, 400, 'a statement is not handed to /witness');
    // A recorder this witness does not serve.
    const other = await generateSealKeySet();
    const foreign = await writeSeal(t1, { by: { keys: other.keys, name: 'Another recorder' } }, other.privateKeys);
    const r = await ask(recorder, t1, foreign);
    assert.equal(r.code, 403);
    assert.equal(r.body.code, 'recorder-not-served');
    // An answer changed on its way: its proof no longer checks, and it is not believed.
    const tampering = async (url, init) => {
      const r = await fetch(url, init);
      if (new URL(url).pathname === '/hello') return r;
      return new Response((await r.text()).replace('"ready":true', '"ready":false'), { status: r.status, headers: r.headers });
    };
    await assert.rejects(witnessClient({ address, token: token.toString(), fetchImpl: tampering }).ask('GET', '/about'), (e) => e.code === 'not-proved');
    // A program that listens where a witness should be, without the token: nothing it says is believed.
    const impostor = createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ session: nodeCrypto.randomBytes(32).toString('base64url'), proof: nodeCrypto.randomBytes(32).toString('base64url') }));
    });
    await new Promise((done) => impostor.listen(0, '127.0.0.1', done));
    try {
      await assert.rejects(witnessClient({ address: `http://127.0.0.1:${impostor.address().port}`, token: token.toString() }).ask('GET', '/about'), (e) => e.code === 'not-the-witness');
    } finally {
      await new Promise((done) => impostor.close(done));
    }
  } finally {
    await w.close();
  }
});

test('its limits: new statements in any hour, the sequences it holds, and the questions it takes on at once', async () => {
  const s = await setting();
  let release;
  const held = new Promise((r) => { release = r; });
  let holding = false;
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits: { statementsPerHour: 1, maxSequences: 1 }, faults: async (step) => { if (step === 'signing' && holding) await held; } });
  try {
    const client = clientOf(s, w);
    const writer = await s.book();
    const t1 = await writer.more(1);
    const s1 = await s.seal(t1);
    assert.equal((await ask(client, t1, s1)).code, 200);
    await writer.add({ seal: s1.record });
    const t2 = await writer.more(1);
    const s2 = await s.seal(t2, { previous: s1.fingerprint });
    const busy = await ask(client, t2, s2, 2);
    assert.equal(busy.code, 429);
    assert.equal(busy.body.code, 'witness-busy');
    assert.equal((await ask(client, t1, s1)).code, 200, 'the seal it holds is answered all the same');
    // Another agent: another sequence, past the most it holds.
    const otherAgent = await makeAgentKeys(tempFolder('provared-wt-'));
    const otherSlip = await signSlip({ agentKeys: otherAgent.keys, passkey: s.passkey });
    const otherBook = `${entryLine({ slip: otherSlip })}\n`;
    const full = await ask(client, otherBook, await s.seal(otherBook));
    assert.equal(full.code, 503);
    assert.equal(full.body.code, 'witness-full');
    // At most WITNESS_MAX_WAITING questions that sign are taken on at once.
    holding = true;
    const asked = Array.from({ length: WITNESS_MAX_WAITING + 3 }, () => ask(client, t1, s1));
    await new Promise((r) => setTimeout(r, 500));
    holding = false;
    release();
    const codes = (await Promise.all(asked)).map((r) => r.code);
    assert.equal(codes.filter((c) => c === 200).length, WITNESS_MAX_WAITING, codes.join(','));
    assert.equal(codes.filter((c) => c === 429).length, 3, codes.join(','));
  } finally {
    await w.close();
  }
});

test('put back to an older copy, it is brought up to date from a recorder\'s book before its operator says it is ready, and then refuses the fork; told it is ready without that, it can be made to sign one', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  await writer.add({ seal: s1.record, witnesses: [(await ask(clientOf(s, w), t1, s1)).body.statement] });
  // A copy of the witness's folder as it stands, kept apart.
  const copy = tempFolder('provared-w-copy-');
  cpSync(s.wfolder, copy, { recursive: true });
  const t2 = await writer.more(2);
  const s2 = await s.seal(t2, { previous: s1.fingerprint });
  await writer.add({ seal: s2.record, witnesses: [(await ask(clientOf(s, w), t2, s2, 2)).body.statement] });
  await w.close();
  const bookFile = join(s.folder, 'book.jsonl');
  writeFileSync(bookFile, writer.book());
  // A fork of the book after seal 1, at seal 2's size.
  const fork = await s.book(t1.split('\n').slice(0, 2).join('\n') + '\n');
  await fork.add({ seal: s1.record });
  const tf = await fork.more(2);
  const sf = await s.seal(tf, { previous: s1.fingerprint });

  // The folder put back to the copy: the witness holds seal 1 only.
  for (const name of ['journal.jsonl', 'state.json', 'journal-mark.json']) cpSync(join(copy, name), join(s.wfolder, name));
  w = await startWitness({ folder: s.wfolder, port: 0 });
  try {
    assert.equal((await w.status()).sequences[0].entries, 2, 'it holds seal 1');
    const done = await updateFrom({ folder: s.wfolder, port: w.port, book: bookFile });
    assert.deepEqual(done, { found: 2, taken: 1, refused: null });
    assert.equal((await w.status()).sequences[0].entries, 5, 'brought up to seal 2');
    assert.equal(journalOf(s.wfolder).at(-1).kind, 'update', 'and that is in its journal');
    await clientOf(s, w, 'operator').ask('POST', '/ready', {});
    const refused = await ask(clientOf(s, w), tf, sf, 2);
    assert.equal(refused.body.refused.code, 'seal-mismatch', 'the fork is refused');
  } finally {
    await w.close();
  }

  // What rests on the operator: put back again, and told it is ready at once, it signs the fork.
  for (const name of ['journal.jsonl', 'state.json', 'journal-mark.json']) cpSync(join(copy, name), join(s.wfolder, name));
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    assert.equal((await ask(clientOf(s, w), tf, sf, 2)).code, 200, 'a witness told it is up to date when it is not can be made to sign a fork');
  } finally {
    await w.close();
  }
});

test('one witness at a time on a folder: a second is refused while the first runs, and a lock left by a process that has ended is taken over', async () => {
  const s = await setting();
  const w = await startWitness({ folder: s.wfolder, port: 0 });
  try {
    await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /Another witness runs on this folder/);
  } finally {
    await w.close();
  }
  assert.ok(!existsSync(join(s.wfolder, 'witness.lock')), 'let go when it stopped');
  // A lock left by a process that has ended.
  const ended = spawn(process.execPath, ['-e', '0']);
  await new Promise((done) => ended.on('close', done));
  writeFileSync(join(s.wfolder, 'witness.lock'), JSON.stringify({ pid: ended.pid, started: new Date().toISOString() }));
  const again = await startWitness({ folder: s.wfolder, port: 0 });
  await again.close();
});

// The commands, run as a person runs them, in a temporary folder and on a port of the test's own.
function runWitness(args, { folder, port }) {
  return new Promise((done) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', witnessFile, ...args], { env: { ...process.env, PROVARED_WITNESS_DIR: folder, PROVARED_WITNESS_PORT: String(port) } });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => done({ code, out: out.trim(), err: err.trim() }));
  });
}

test('the commands: init, start, status, ready, update and stop', async () => {
  const s = await setting();
  const folder = tempFolder('provared-w-');
  const port = await freePort();
  const made = await runWitness(['init', '--name', 'Test witness', '--recorder', s.sealer], { folder, port });
  assert.equal(made.code, 0, made.err);
  assert.match(made.out, /The fingerprint of its key set: [A-Za-z0-9_-]{43}/);
  // Started in the background; it is stopped with its own command.
  const start = () => spawn(process.execPath, ['--disable-warning=ExperimentalWarning', witnessFile, 'start'], { env: { ...process.env, PROVARED_WITNESS_DIR: folder, PROVARED_WITNESS_PORT: String(port) }, stdio: 'ignore' });
  const answers = async () => {
    for (let i = 0; i < 80; i++) {
      try {
        if ((await fetch(`http://127.0.0.1:${port}/nothing`)).status === 404) return true;
      } catch { /* not yet */ }
      await new Promise((r) => setTimeout(r, 250));
    }
    return false;
  };
  let child = start();
  try {
    assert.ok(await answers(), 'it answers');
    const shown = await runWitness(['status'], { folder, port });
    assert.equal(shown.code, 0, shown.err);
    assert.equal(JSON.parse(shown.out).ready, false, 'a new witness, too, signs nothing until it is told it may');
    assert.equal((await runWitness(['ready'], { folder, port })).code, 0);
    const client = witnessClient({ address: `http://127.0.0.1:${port}`, token: readToken(witnessFiles(folder).token) });
    const writer = await s.book();
    const t1 = await writer.more(1);
    const s1 = await s.seal(t1);
    await writer.add({ seal: s1.record, witnesses: [(await ask(client, t1, s1)).body.statement] });
    writeFileSync(join(s.folder, 'book.jsonl'), writer.book());
    assert.equal((await runWitness(['stop'], { folder, port })).code, 0);
  } finally {
    child.kill();
  }
  child = start();
  try {
    assert.ok(await answers(), 'it answers again');
    assert.equal(JSON.parse((await runWitness(['status'], { folder, port })).out).ready, false, 'started from what it kept: not ready');
    const updated = await runWitness(['update', join(s.folder, 'book.jsonl')], { folder, port });
    assert.match(updated.out, /Of the 1 seals with a statement of this witness, it took 0/);
    const ready = await runWitness(['ready'], { folder, port });
    assert.equal(ready.code, 0, ready.err);
    assert.equal(JSON.parse((await runWitness(['status'], { folder, port })).out).ready, true);
    assert.equal((await runWitness(['stop'], { folder, port })).code, 0);
  } finally {
    child.kill();
  }
  assert.equal((await runWitness(['nothing'], { folder, port })).code, 2);
});
