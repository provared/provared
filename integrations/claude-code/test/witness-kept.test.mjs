// What the witness (witness.mjs) keeps on its disk, and what it gives out:
// nothing that is not saved, by any route; nothing at all once a save has
// failed; nothing signed at any start until its operator says so; a journal
// begun again at each checkpoint and read a line at a time; one witness to a
// folder; and a sequence forgotten only at its operator's word. Every
// witness here works in a temporary folder and on a free port.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { bookIdentity, entryLine, fingerprint, fromBase64url, generateSealKeySet, keySetFingerprint, openRecorder, thumbprint, toBase64url, utf8, witnessProof, writeSeal } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { initWitness, readToken, startWitness, witnessClient, witnessFiles } = await import('../witness.mjs');
const { makeAgentKeys } = await import('../recorder.mjs');
const { refusedStart, signSlip, tempFolder } = await import('./world.mjs');

const witnessFile = fileURLToPath(new URL('../witness.mjs', import.meta.url));
const lineCount = (text) => text.split('\n').filter(Boolean).length;
const firstOf = (text) => text.split('\n')[0];
const journalOf = (folder) => readFileSync(witnessFiles(folder).journal, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

/** A recorder's book made with the library, the recorder's keys to seal it, and a witness made for it (not started). */
async function setting() {
  const folder = tempFolder('provared-wk-');
  const agent = await makeAgentKeys(folder);
  const passkey = await developmentPasskey();
  const slip = await signSlip({ agentKeys: agent.keys, passkey });
  const slipFingerprint = await fingerprint(fromBase64url(slip.payload));
  const recorder = await generateSealKeySet();
  const by = { keys: recorder.keys, name: 'A recorder (test)' };
  const sealer = await keySetFingerprint(recorder.keys);
  const issuer = await thumbprint(passkey.key);
  let calls = 0;
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
  const made = await initWitness({ folder: wfolder, recorders: [sealer] });
  return { folder, agent, passkey, slip, recorder, by, sealer, issuer, book, seal, wfolder, made };
}
const clientOf = (s, w, role = 'recorder') => witnessClient({ address: `http://127.0.0.1:${w.port}`, token: readToken(role === 'recorder' ? witnessFiles(s.wfolder).token : witnessFiles(s.wfolder).operator), role });
async function ask(client, text, sealed, held = null) {
  return client.ask('POST', '/witness', { entry: { seal: sealed.record }, proof: (await witnessProof(text, lineCount(text), held)).map(toBase64url), first: firstOf(text) });
}

test('a journal line that cannot be written: nothing of that seal is given out, by any route, and it gives out nothing more until it is started again', async () => {
  const s = await setting();
  let failing = false;
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true, faults: (step) => { if (step === 'journal' && failing) throw new Error('the disk is full'); } });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(t1)));
  const t2 = (await writer.add({ seal: s1.record }), await writer.more(2));
  const s2 = await s.seal(t2, { previous: s1.fingerprint });
  const statements = [];
  try {
    const r1 = await ask(clientOf(s, w), t1, s1);
    assert.equal(r1.code, 200);
    statements.push(r1.body.statement);
    failing = true;
    const r2 = await ask(clientOf(s, w), t2, s2, 2);
    assert.equal(r2.code, 503);
    assert.equal(r2.body.code, 'witness-stopped');
    assert.equal(r2.body.statement, undefined, 'no statement in the answer');
    failing = false;
    // Every other route: nothing of seal 2, and nothing at all once a save has failed.
    const latest = await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`);
    assert.equal(latest.code, 503, '/latest gives nothing');
    assert.equal(latest.body.latest, undefined);
    assert.equal((await ask(clientOf(s, w), t2, s2, 2)).code, 503, 'the same seal again: nothing');
    assert.equal((await ask(clientOf(s, w), t1, s1)).code, 503, 'nor the seal it held');
    const op = clientOf(s, w, 'operator');
    assert.equal((await op.ask('POST', '/ready', {})).code, 503, 'it cannot be told it may sign again');
    assert.equal((await op.ask('POST', '/update', { entry: { seal: s2.record, witnesses: [] }, proof: [], first: firstOf(t2) })).code, 503);
    const about = await clientOf(s, w).ask('GET', '/about');
    assert.equal(about.body.ready, false);
    const status = (await op.ask('GET', '/status')).body;
    assert.match(status.problem, /could not be kept on the disk \(the disk is full\)/);
    assert.equal(status.sequences[0].entries, 2, 'its status names what is saved: seal 1');
    assert.equal(journalOf(s.wfolder).length, 1);
  } finally {
    await w.close();
  }
  // Started again: it holds seal 1, and has given out no statement for seal 2.
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    const holds = await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`);
    assert.equal(holds.body.latest.seal.payload, s1.record.payload);
    // So a seal of another history at seal 2's size can be signed, and still no two statements of this witness stand at one size.
    const fork = await s.book(t1.split('\n').slice(0, 2).join('\n') + '\n');
    await fork.add({ seal: s1.record });
    const tf = await fork.more(2);
    const sf = await s.seal(tf, { previous: s1.fingerprint });
    const rf = await ask(clientOf(s, w), tf, sf, 2);
    assert.equal(rf.code, 200);
    statements.push(rf.body.statement);
    const sizes = statements.map((st) => JSON.parse(Buffer.from(st.payload, 'base64url').toString('utf8')).size);
    assert.equal(new Set(sizes).size, sizes.length, 'one statement for each size');
  } finally {
    await w.close();
  }
});

test('while a statement is being saved, what it holds is given out as it was last saved, never from its memory', async () => {
  const s = await setting();
  let hold = null;
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true, faults: async (step) => { if (step === 'journaled' && hold) await hold; } });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(t1)));
  try {
    assert.equal((await ask(clientOf(s, w), t1, s1)).code, 200);
    await writer.add({ seal: s1.record });
    const t2 = await writer.more(2);
    const s2 = await s.seal(t2, { previous: s1.fingerprint });
    let release;
    hold = new Promise((r) => { release = r; });
    const signing = ask(clientOf(s, w), t2, s2, 2);
    await new Promise((r) => setTimeout(r, 500));
    const meanwhile = await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`);
    assert.equal(meanwhile.body.latest.seal.payload, s1.record.payload, 'seal 2 is not saved yet: seal 1 is what is given out');
    hold = null;
    release();
    assert.equal((await signing).code, 200);
    assert.equal((await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`)).body.latest.seal.payload, s2.record.payload);
  } finally {
    await w.close();
  }
});

test('a state that cannot be saved after its journal line: nothing is given out; started again, the line is taken and its statement given', async () => {
  const s = await setting();
  let failing = false;
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true, faults: (step) => { if (step === 'journaled' && failing) throw new Error('the disk is full'); } });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(t1)));
  try {
    failing = true;
    assert.equal((await ask(clientOf(s, w), t1, s1)).code, 503);
    assert.equal((await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`)).code, 503, 'on the journal but not given out');
  } finally {
    await w.close();
  }
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    const holds = await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`);
    assert.deepEqual(holds.body.latest.statement, journalOf(s.wfolder)[0].entry.witnesses[0], 'given out once it is on the disk');
  } finally {
    await w.close();
  }
});

test('at every start, the first included, it signs nothing until its operator says so: a folder put back to a copy taken after init does not sign a fork', async () => {
  const s = await setting();
  const copy = tempFolder('provared-w-copy-');
  cpSync(s.wfolder, copy, { recursive: true });
  let w = await startWitness({ folder: s.wfolder, port: 0 });
  const a = await s.book();
  const ta = await a.more(1);
  const sa = await s.seal(ta);
  try {
    const first = await ask(clientOf(s, w), ta, sa);
    assert.equal(first.code, 409);
    assert.equal(first.body.refused.code, 'witness-not-ready', 'a new witness too');
    const status = (await clientOf(s, w, 'operator').ask('GET', '/status')).body;
    assert.equal(status.ready, false);
    assert.match(status.notReady, /At every start/);
    assert.equal((await clientOf(s, w, 'operator').ask('POST', '/ready', {})).code, 200);
    assert.equal((await ask(clientOf(s, w), ta, sa)).code, 200);
  } finally {
    await w.close();
  }
  // Put back to the copy: it does not know, and signs nothing until told.
  for (const name of ['journal.jsonl']) cpSync(join(copy, name), join(s.wfolder, name));
  // The copy holds neither a state nor a journal mark: they are written at the first start.
  for (const name of ['state.json', 'journal-mark.json']) renameSync(join(s.wfolder, name), join(s.wfolder, `${name}.aside`));
  w = await startWitness({ folder: s.wfolder, port: 0 });
  try {
    const b = await s.book();
    const tb = await b.more(1);
    const sb = await s.seal(tb);
    const r = await ask(clientOf(s, w), tb, sb);
    assert.equal(r.code, 409);
    assert.equal(r.body.refused.code, 'witness-not-ready');
  } finally {
    await w.close();
  }
});

test('every few lines a checkpoint is written and the journal begun again; a start takes the newer of the state and the checkpoint, and mends a stop between the steps', async () => {
  const s = await setting();
  const limits = { journalLines: 2 };
  const f = witnessFiles(s.wfolder);
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  const writer = await s.book();
  const seals = [];
  let held = null;
  const next = async (wit) => {
    const text = await writer.more(1);
    const sealed = await s.seal(text, seals.length ? { previous: seals.at(-1).fingerprint } : {});
    const r = await ask(clientOf(s, wit), text, sealed, held);
    assert.equal(r.code, 200, JSON.stringify(r.body));
    await writer.add({ seal: sealed.record, witnesses: [r.body.statement] });
    seals.push(sealed);
    held = lineCount(text);
    return r.body.statement;
  };
  try {
    await next(w);
    await next(w);
    assert.ok(existsSync(f.checkpoint), 'a checkpoint after two lines');
    assert.equal(readFileSync(f.journal, 'utf8'), '', 'and the journal begun again');
    assert.equal(JSON.parse(readFileSync(f.checkpoint, 'utf8')).segment, 2);
    await next(w);
    assert.deepEqual(journalOf(s.wfolder).map((l) => [l.seg, l.n]), [[2, 1]]);
    assert.equal((await w.status()).journal.segment, 2);
  } finally {
    await w.close();
  }
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(writer.book())));
  const latestIs = async (wit, sealed) => assert.equal((await clientOf(s, wit).ask('GET', `/latest?sequence=${identity}`)).body.latest.seal.payload, sealed.record.payload);
  // The state lost: rebuilt from the checkpoint and the journal.
  renameSync(f.state, `${f.state}.aside`);
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  try {
    await latestIs(w, seals[2]);
    assert.match((await w.status()).notes.join(' '), /rebuilt from the checkpoint and the journal/);
  } finally {
    await w.close();
  }
  // A stop after the checkpoint was written and before the journal was begun again.
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits, faults: (step) => { if (step === 'checkpointed') throw new Error('stopped'); } });
  try {
    await next(w);
    assert.equal((await w.status()).ready, false, 'it gives out nothing more');
  } finally {
    await w.close();
  }
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  try {
    await latestIs(w, seals[3]);
    assert.match((await w.status()).notes.join(' '), /older than its checkpoint|begun again/);
    assert.equal(readFileSync(f.journal, 'utf8'), '', 'the journal begun again at the start');
    await next(w);
    assert.deepEqual(journalOf(s.wfolder).map((l) => l.seg), [3]);
  } finally {
    await w.close();
  }
  // A journal of a later segment than anything kept: refused.
  const journal = readFileSync(f.journal, 'utf8');
  writeFileSync(f.journal, journal.replace('{"seg":3,', '{"seg":4,'));
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /what it kept is older than its journal/);
  writeFileSync(f.journal, journal);
});

test('the journal is read a line at a time: a line its state reflects is read only as far as its number, every later one in full; numbers out of order stop the start', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  await ask(clientOf(s, w), t1, s1);
  await w.close();
  const f = witnessFiles(s.wfolder);
  const whole = readFileSync(f.journal, 'utf8');
  // The body of a line the state reflects, changed past its beginning: not read, so the start goes on.
  writeFileSync(f.journal, whole.replace('"proof":[', '"proof":["not read"'));
  w = await startWitness({ folder: s.wfolder, port: 0 });
  await w.close();
  // The same line, not reflected (the state set aside): read, and refused.
  const state = readFileSync(f.state, 'utf8');
  renameSync(f.state, `${f.state}.aside`);
  writeFileSync(f.journal, whole.replace('"first":"', '"first":7,"x":"'));
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /not a line this witness writes/);
  // A line given twice: its numbers are out of order.
  writeFileSync(f.state, state);
  writeFileSync(f.journal, whole + whole);
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /numbered 1 where 2 was due/);
  writeFileSync(f.journal, whole);
});

test('it listens on 127.0.0.1 only, and takes no update for a recorder it does not serve', async () => {
  const s = await setting();
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    assert.equal((await fetch(`http://127.0.0.1:${w.port}/nothing`)).status, 404);
    const elsewhere = ['[::1]', ...Object.values(networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address)];
    for (const host of elsewhere) {
      await assert.rejects(fetch(`http://${host}:${w.port}/nothing`, { signal: AbortSignal.timeout(3000) }), () => true, `nothing answers at ${host}`);
    }
    const other = await generateSealKeySet();
    const writer = await s.book();
    const t1 = await writer.more(1);
    const foreign = await writeSeal(t1, { by: { keys: other.keys, name: 'Another recorder' } }, other.privateKeys);
    const r = await clientOf(s, w, 'operator').ask('POST', '/update', { entry: { seal: foreign.record, witnesses: [] }, proof: (await witnessProof(t1, 2, null)).map(toBase64url), first: firstOf(t1) });
    assert.equal(r.code, 403);
    assert.equal(r.body.code, 'recorder-not-served');
  } finally {
    await w.close();
  }
});

test('two starts that find the same stale lock: one runs, the other does not', async () => {
  const s = await setting();
  const ended = spawn(process.execPath, ['-e', '0']);
  await new Promise((done) => ended.on('close', done));
  const runs = [];
  for (let round = 0; round < 3; round++) {
    writeFileSync(join(s.wfolder, 'witness.lock'), JSON.stringify({ pid: ended.pid, started: new Date().toISOString() }));
    // Each start, a program of its own, waits for the same moment and then starts, and stays a second and a half.
    const at = Date.now() + 1500;
    const script = `const { startWitness } = await import(${JSON.stringify(new URL('../witness.mjs', import.meta.url).href)}); while (Date.now() < ${at}); try { const w = await startWitness({ folder: ${JSON.stringify(s.wfolder)}, port: 0 }); console.log('started'); await new Promise((r) => setTimeout(r, 1500)); await w.close(); } catch (e) { console.log('refused: ' + e.message.slice(0, 60)); }`;
    const both = await Promise.all([1, 2].map(() => new Promise((done) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', script], { env: process.env });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.on('close', () => done(out.trim()));
    })));
    runs.push(both);
    assert.equal(both.filter((o) => o === 'started').length, 1, both.join(' | '));
  }
  assert.ok(!existsSync(join(s.wfolder, 'witness.lock.takeover')), 'the second file is let go');
});

test('forget: only its operator can make it forget a sequence, which it then holds no more, across a restart; and a new sequence starts only from a permission whose passkey signature passes', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(t1)));
  try {
    assert.equal((await ask(clientOf(s, w), t1, s1)).code, 200);
    assert.equal((await clientOf(s, w).ask('POST', '/forget', { sequence: identity })).code, 403, 'not with a recorder\'s token');
    const op = clientOf(s, w, 'operator');
    assert.equal((await op.ask('POST', '/forget', { sequence: 'A'.repeat(43) })).code, 404);
    assert.equal((await op.ask('POST', '/forget', { sequence: identity })).code, 200);
    assert.equal((await op.ask('GET', '/status')).body.sequences.length, 0);
    assert.equal(journalOf(s.wfolder).at(-1).kind, 'forget');
  } finally {
    await w.close();
  }
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  try {
    assert.equal((await clientOf(s, w).ask('GET', `/latest?sequence=${identity}`)).body.latest, null, 'still forgotten after a restart');
    // What forgetting means: it now signs whatever it is first shown for that sequence, a second history too.
    const other = await s.book();
    const to = await other.more(1);
    assert.equal((await ask(clientOf(s, w), to, await s.seal(to))).code, 200);
    // A permission whose passkey signature does not pass starts no sequence.
    const agent2 = await makeAgentKeys(tempFolder('provared-wk-'));
    const bad = await signSlip({ agentKeys: agent2.keys, passkey: s.passkey, sign: async (challenge) => {
      const r = await s.passkey.sign(challenge);
      r.signature[r.signature.length - 3] ^= 1;
      return r;
    } });
    const badBook = `${entryLine({ slip: bad })}\n`;
    const refused = await ask(clientOf(s, w), badBook, await s.seal(badBook));
    assert.equal(refused.code, 409);
    assert.match(refused.body.refused.message, /does not pass its check|could not check the passkey/);
  } finally {
    await w.close();
  }
});

test('a new sequence does not start where the device cannot check the passkey\'s signature on the permission: refused as check-failed', async () => {
  const s = await setting();
  // The development passkey signs with ES256: treated here as not built into this device.
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true, withoutMethods: ['ES256'] });
  try {
    const writer = await s.book();
    const t1 = await writer.more(1);
    const r = await ask(clientOf(s, w), t1, await s.seal(t1));
    assert.equal(r.code, 409, JSON.stringify(r.body));
    assert.equal(r.body.refused.code, 'check-failed');
    assert.match(r.body.refused.message, /could not check the passkey's signature/);
    assert.equal((await w.status()).sequences.length, 0, 'it holds nothing');
  } finally {
    await w.close();
  }
});

test('a sequence forgotten while the witness is not ready leaves it not ready: it signs nothing until its operator says so', async () => {
  const s = await setting();
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  const s1 = await s.seal(t1);
  const identity = await bookIdentity(s.recorder.keys, utf8(firstOf(t1)));
  try {
    assert.equal((await ask(clientOf(s, w), t1, s1)).code, 200);
  } finally {
    await w.close();
  }
  w = await startWitness({ folder: s.wfolder, port: 0 });
  try {
    assert.equal((await clientOf(s, w, 'operator').ask('POST', '/forget', { sequence: identity })).code, 200);
    assert.equal((await w.status()).ready, false, 'still not ready');
    const other = await s.book();
    const to = await other.more(1);
    const r = await ask(clientOf(s, w), to, await s.seal(to));
    assert.equal(r.code, 409, JSON.stringify(r.body));
    assert.equal(r.body.refused.code, 'witness-not-ready', 'it signs nothing, a second history least of all');
  } finally {
    await w.close();
  }
});

test('a journal that holds lines of two segments, an earlier one first, stops the start', async () => {
  const s = await setting();
  const limits = { journalLines: 2 };
  const f = witnessFiles(s.wfolder);
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  const writer = await s.book();
  let held = null;
  let previous = null;
  let firstLine = null;
  try {
    for (let i = 0; i < 3; i++) {
      const text = await writer.more(1);
      const sealed = await s.seal(text, previous ? { previous } : {});
      const r = await ask(clientOf(s, w), text, sealed, held);
      assert.equal(r.code, 200, JSON.stringify(r.body));
      await writer.add({ seal: sealed.record, witnesses: [r.body.statement] });
      if (i === 0) firstLine = readFileSync(f.journal, 'utf8');
      previous = sealed.fingerprint;
      held = lineCount(text);
    }
  } finally {
    await w.close();
  }
  const now = readFileSync(f.journal, 'utf8');
  assert.deepEqual(journalOf(s.wfolder).map((l) => [l.seg, l.n]), [[2, 1]]);
  // A line of segment 1, put back before the line of segment 2.
  writeFileSync(f.journal, firstLine + now);
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /holds lines of two segments/);
  writeFileSync(f.journal, now);
});

test('a journal line longer than any the witness writes stops the start before it is read whole', async () => {
  const s = await setting();
  const w = await startWitness({ folder: s.wfolder, port: 0, ready: true });
  const writer = await s.book();
  const t1 = await writer.more(1);
  try {
    assert.equal((await ask(clientOf(s, w), t1, await s.seal(t1))).code, 200);
  } finally {
    await w.close();
  }
  const f = witnessFiles(s.wfolder);
  const whole = readFileSync(f.journal, 'utf8');
  // Two megabytes on one line, after a beginning the witness writes: read whole, it would not be JSON.
  writeFileSync(f.journal, `${whole}{"seg":1,"n":2,"kind":"witness",${'"x":0,'.repeat(350000)}"y":0}\n`);
  await refusedStart(startWitness, { folder: s.wfolder, port: 0 }, /longer than any line this witness writes/);
  writeFileSync(f.journal, whole);
});

test('with its state lost, a journal emptied or cut short is seen by its mark, and the start stops; a mark that is not one it writes stops it too', async () => {
  const s = await setting();
  const limits = { journalLines: 3 };
  const f = witnessFiles(s.wfolder);
  let w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  const writer = await s.book();
  let held = null;
  let previous = null;
  const next = async () => {
    const text = await writer.more(1);
    const sealed = await s.seal(text, previous ? { previous } : {});
    const r = await ask(clientOf(s, w), text, sealed, held);
    assert.equal(r.code, 200, JSON.stringify(r.body));
    await writer.add({ seal: sealed.record, witnesses: [r.body.statement] });
    previous = sealed.fingerprint;
    held = lineCount(text);
  };
  try {
    await next();
    await next();
  } finally {
    await w.close();
  }
  const saved = JSON.parse(readFileSync(f.mark, 'utf8'));
  assert.deepEqual([saved.type, saved.segment, saved.lines], ['provared.witness-journal-mark.v1', 1, 2]);
  const whole = readFileSync(f.journal, 'utf8');
  renameSync(f.state, `${f.state}.aside`);
  // Emptied: with no checkpoint, it would start holding nothing, and sign a second history.
  writeFileSync(f.journal, '');
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /journal-mark\.json says that 2 lines of the journal's segment 1 were saved, and the start finds 0/);
  // Cut short to its first line: it would start from the older seal.
  writeFileSync(f.journal, `${whole.split('\n')[0]}\n`);
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /says that 2 lines .* finds 1/);
  // Whole: rebuilt from the journal, as before.
  writeFileSync(f.journal, whole);
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  try {
    assert.equal((await w.status()).sequences[0].entries, held, 'it holds the latest seal');
    // A third line: a checkpoint, and the journal begun again; then a line of segment 2.
    await next();
    await next();
    assert.deepEqual(journalOf(s.wfolder).map((l) => [l.seg, l.n]), [[2, 1]]);
  } finally {
    await w.close();
  }
  // The state and the checkpoint lost, and the journal emptied: the mark is of a later segment than anything kept.
  const journal2 = readFileSync(f.journal, 'utf8');
  renameSync(f.state, `${f.state}.aside2`);
  renameSync(f.checkpoint, `${f.checkpoint}.aside`);
  writeFileSync(f.journal, '');
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /segment 2 were saved, and the start finds nothing kept beyond segment 1/);
  renameSync(`${f.checkpoint}.aside`, f.checkpoint);
  writeFileSync(f.journal, journal2);
  // A mark that is not one it writes.
  const mark = readFileSync(f.mark, 'utf8');
  writeFileSync(f.mark, '{"type":"provared.witness-journal-mark.v1","segment":0,"lines":1}');
  await refusedStart(startWitness, { folder: s.wfolder, port: 0, limits }, /is not a journal mark this witness writes/);
  writeFileSync(f.mark, mark);
  w = await startWitness({ folder: s.wfolder, port: 0, ready: true, limits });
  try {
    assert.equal((await w.status()).sequences[0].entries, held, 'rebuilt from the checkpoint and the journal');
  } finally {
    await w.close();
  }
});
