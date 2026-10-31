// The central sealer as a program: a recorder sends it the leaf
// fingerprints of its book's lines and asks for seals; the seals check in
// the book; the state is saved before a seal is given out, and carried on
// after a start; a question proves that it comes from a recorder the sealer
// serves, and an answer that it comes from the sealer, without the token
// being sent; one state holds every recorder's books, each book belongs to
// the recorder that started it, and a recorder starts books only with
// permissions for its own agents, up to its own number of books. Every
// server listens on 127.0.0.1. Signing a seal takes about a second and a
// half, so these tests seal sparingly.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import v8 from 'node:v8';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { assembleSlip, checkBook, fingerprint, formatTime, fromBase64url, generateKeySet, keySetFingerprint, leafFingerprint, openRecorder, prepareSlip, thumbprint, toBase64url, writeBook } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { addRecorder, connectSealer, makeKeys, releaseUnsealed, sealerFiles, sealerHmac, startSealer, writeDurably, MAX_WAITING_BYTES, QUESTION_WINDOW_MS } = await import('../sealer.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));
const LIBRARY_HOOK = new URL('./local-library.mjs', import.meta.url).href;
const QUESTION = 'provared sealer v1: a recorder\'s question';
const HEAD = 'provared sealer v1: a recorder\'s question, before its body';

const made = [];
process.on('exit', () => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});
function tempFolder() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-sealer-'));
  made.push(dir);
  return dir;
}

// Each recorder's agent, by the recorder's name: one key set, kept for every test.
const agentKeys = new Map();
const agentOf = (name) => {
  if (!agentKeys.has(name)) agentKeys.set(name, generateKeySet());
  return agentKeys.get(name);
};
const agentPrint = async (name) => keySetFingerprint((await agentOf(name)).keys);

// A permission for a recorder's agent, signed with the development stand-in for a passkey: a new one each time, so a
// new first line for a new book.
async function permission(name = 'agent-one', purpose = 'A book for the tests.') {
  const agent = await agentOf(name);
  const passkey = await developmentPasskey();
  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: 'Sam Example (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'Development agent', keys: agent.keys },
    actions: ['provared.code.read'],
    limits: [],
    with: [],
    validFrom: formatTime(now - 60 * 1000),
    validUntil: formatTime(now + 24 * 3600 * 1000),
    purpose,
  });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  return { line: writeBook([{ slip }]).trimEnd(), slipFingerprint: await fingerprint(fromBase64url(slip.payload)), issuerKeys: [await thumbprint(passkey.key)], agent };
}

// A sealer's folder with its settings, its keys and its recorders, each named with its own agent.
async function sealerFolder(settings = {}, recorders = ['agent-one'], rules = {}) {
  const folder = tempFolder();
  writeFileSync(join(folder, 'sealer.json'), JSON.stringify({ name: 'Example central sealer (invented)', port: 0, ...settings }));
  await makeKeys(folder);
  const tokens = {};
  for (const name of recorders) tokens[name] = await addRecorder(folder, name, { agents: [await agentPrint(name)], ...rules[name] });
  return { folder, tokens };
}

// A small book of a recorder's agent: its permission, and two lines after it.
async function smallBook(name = 'agent-one') {
  const p = await permission(name);
  const lines = [p.line, '{"note":"one"}', '{"note":"two"}'];
  return { lines, line: lines[0], first: toBase64url(await leafFingerprint(lines[0])), leaves: await Promise.all(lines.map(leafFingerprint)) };
}

const lineOf = (lines) => lines.join('\n') + '\n';
const onDisk = (folder) => JSON.parse(readFileSync(sealerFiles(folder).state, 'utf8'));

// A start that must be refused: where it is not, the sealer is closed at once, so that the test fails and never hangs.
async function refusedStart(options, pattern) {
  await assert.rejects(
    startSealer(options).then(async (running) => {
      await running.close();
      return running;
    }),
    pattern,
  );
}

// A question made by hand: its headers, with both proofs made under "key" (a recorder's token, or another), and its
// body. The first proof covers "length", the body's length unless another is given.
function signed({ recorder, key, path, body = {}, time = Date.now(), nonce = toBase64url(nodeCrypto.randomBytes(32)), raw, length }) {
  const bytes = raw ?? Buffer.from(JSON.stringify(body));
  const sha = nodeCrypto.createHash('sha256').update(bytes).digest('base64url');
  const token = Buffer.from(key, 'base64url');
  const head = sealerHmac(token, HEAD, recorder, path, String(time), nonce, String(length ?? bytes.length)).toString('base64url');
  const proof = sealerHmac(token, QUESTION, recorder, path, String(time), nonce, sha).toString('base64url');
  const headers = { 'content-type': 'application/json', 'provared-sealer-recorder': recorder, 'provared-sealer-time': String(time), 'provared-sealer-nonce': nonce, 'provared-sealer-head': head, 'provared-sealer-proof': proof };
  return { headers, bytes };
}

// A question sent by hand, as often as it is called.
function question({ address, path, ...rest }) {
  const { headers, bytes } = signed({ path, ...rest });
  return () => fetch(`${address}${path}`, { method: 'POST', headers, body: bytes });
}

// A question whose body is declared and sent only in part ("bytes" of it, out of "length"); it gives the status of
// the answer, or "closed". Each is kept in "opened", to be let go at the end of a test.
function sendPart(address, path, headers, bytes, length, opened) {
  return new Promise((done) => {
    const req = http.request(`${address}${path}`, { method: 'POST', headers: { ...headers, 'content-length': String(length) } }, (res) => {
      res.resume();
      done(res.statusCode);
    });
    opened.push(req);
    req.on('error', () => done('closed'));
    req.write(typeof bytes === 'number' ? Buffer.alloc(bytes, 0x20) : bytes);
  });
}
const within = (promise, ms) => Promise.race([promise, new Promise((done) => setTimeout(() => done('no answer'), ms))]);
const pause = (ms) => new Promise((ok) => setTimeout(ok, ms));

test('a recorder sends leaf fingerprints, asks for seals, and the seals check in its book; the state is carried on after a start', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const about = await client.about();
    assert.equal(about.sealer, running.fingerprint);
    // A book of its agent's permission and random lines: the checker needs no more to check a seal's tree.
    const lines = [(await permission()).line, ...Array.from({ length: 5 }, (_, i) => JSON.stringify({ n: i }))];
    const first = toBase64url(await leafFingerprint(lines[0]));
    const leaves = await Promise.all(lines.map(leafFingerprint));
    // A book is started with its first line itself.
    assert.equal((await client.extend(first, 0, leaves.slice(0, 4))).refused.code, 'bad-field');
    assert.deepEqual(await client.extend(first, 0, leaves.slice(0, 4), { line: lines[0] }), { size: 4 });
    // A book started is saved before the answer: it binds its first line to its recorder. It is kept at its first line.
    assert.deepEqual(onDisk(folder).books, [{ first, number: 1, closed: false, recorder: 'agent-one' }]);
    const step = await client.extend(first, 2, leaves.slice(2));
    assert.equal(step.refused.code, 'out-of-step');
    assert.equal(step.size, 4);
    assert.deepEqual(await client.extend(first, 4, leaves.slice(4)), { size: 6 });
    const s1 = await client.seal(first, { previous: null });
    assert.ok(s1.entry, JSON.stringify(s1.refused));
    assert.equal(s1.state, undefined, 'the state stays with the sealer');
    const trust = { sealKeys: [running.fingerprint] };
    const book1 = lineOf([...lines, s1.line]);
    assert.deepEqual((await checkBook(book1, trust)).problems, []);
    // The state on the disk holds the seal.
    assert.equal(onDisk(folder).books[0].latest.entry.seal.payload, s1.entry.seal.payload);
    // A line taken in after the seal is not kept: started again, the sealer stands at its latest seal.
    assert.deepEqual(await client.extend(first, 6, [await leafFingerprint(s1.line)]), { size: 7 });
    await running.close();

    // Started again: it carries on from its state.
    const again = await startSealer({ folder });
    try {
      const c2 = connectSealer({ address: again.address, recorder: 'agent-one', token: tokens['agent-one'] });
      assert.equal((await c2.held(first)).latest, s1.fingerprint);
      assert.equal((await c2.held(first)).size, 6);
      assert.deepEqual(await c2.latest(first), { entry: s1.entry, line: s1.line, fingerprint: s1.fingerprint });
      const more = [s1.line, '{"n":6}'];
      assert.equal((await c2.extend(first, 7, await Promise.all(more.map(leafFingerprint)))).refused.code, 'out-of-step');
      assert.deepEqual(await c2.extend(first, 6, await Promise.all(more.map(leafFingerprint))), { size: 8 });
      assert.equal((await c2.seal(first, { previous: null })).refused.code, 'not-up-to-date');
      const s2 = await c2.seal(first, { previous: s1.fingerprint });
      assert.deepEqual((await checkBook(lineOf([...lines, ...more, s2.line]), trust)).problems, []);
    } finally {
      await again.close();
    }
  } finally {
    await running.close();
  }
});

test('the seal joins a real book through the stub writer\'s add', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  try {
    const p = await permission();
    const writer = await openRecorder({ book: `${p.line}\n`, slip: p.slipFingerprint, privateKeys: p.agent.privateKeys, issuerKeys: p.issuerKeys, options: { sealKeys: [running.fingerprint] } });
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const first = toBase64url(await leafFingerprint(p.line));
    await client.extend(first, 0, [await leafFingerprint(p.line)], { line: p.line });
    const s = await client.seal(first, { previous: null });
    await writer.add(s.entry);
    const answer = await writer.check();
    assert.deepEqual(answer.problems, []);
    assert.equal(answer.summary.intact, true);
  } finally {
    await running.close();
  }
});

test('a seal is never given out before the state that holds it is saved; after a failed save the sealer gives nothing', async () => {
  const { folder, tokens } = await sealerFolder();
  const { lines, line, first, leaves } = await smallBook();
  const files = sealerFiles(folder);
  let running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    await client.extend(first, 0, leaves, { line });
    // The state can no longer be written: its temporary file's place is taken by a folder.
    mkdirSync(`${files.state}.tmp`);
    // A question sent while the seal is being signed waits behind it, and is taken up after the failed save.
    const sealing = client.seal(first, { previous: null });
    await new Promise((ok) => setTimeout(ok, 300));
    const queued = client.held(first);
    await assert.rejects(sealing, (e) => e.code === 'sealer-stopped' && e.status === 503);
    await assert.rejects(queued, (e) => e.code === 'sealer-stopped' && e.status === 503);
    // Nothing more is given, by any route, whatever the question holds.
    await assert.rejects(client.latest(first), (e) => e.code === 'sealer-stopped');
    await assert.rejects(client.held(first), (e) => e.code === 'sealer-stopped');
    const notJsonTwice = question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/held', raw: Buffer.from('not json') });
    const notJson = await notJsonTwice();
    assert.equal(notJson.status, 503);
    assert.equal((await notJson.json()).refused.code, 'sealer-stopped');
    // Answered before its number used once is kept: the same question sent again is answered the same way.
    const again = await notJsonTwice();
    assert.equal(again.status, 503);
    assert.equal((await again.json()).refused.code, 'sealer-stopped');
    await running.close();
    // The state on the disk holds no seal; started again, the seal it never gave out is not there.
    rmSync(`${files.state}.tmp`, { recursive: true });
    assert.equal(onDisk(folder).books[0].latest, undefined);
    running = await startSealer({ folder });
    const c2 = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    assert.equal(await c2.latest(first), null);
    const s = await c2.seal(first, { previous: null });
    assert.deepEqual((await checkBook(lineOf([...lines, s.line]), { sealKeys: [running.fingerprint] })).problems, []);
  } finally {
    await running.close();
  }
});

test('a question proves its recorder, and an answer its sealer, without the token being sent', async () => {
  let now = Date.now();
  const { folder, tokens } = await sealerFolder({}, ['agent-one', 'agent-two']);
  const running = await startSealer({ folder, clock: () => now });
  try {
    const { line, first, leaves } = await smallBook();
    // Another recorder's token, or a made-up one: refused.
    const wrong = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-two'], clock: () => now });
    await assert.rejects(wrong.about(), /did not prove that it comes from the sealer/);
    const unknown = connectSealer({ address: running.address, recorder: 'agent-three', token: tokens['agent-one'], clock: () => now });
    await assert.rejects(unknown.about(), /did not prove/);
    // A question whose proof is made under another token is refused (401), whatever the answer would prove.
    const forged = await question({ address: running.address, recorder: 'agent-one', key: tokens['agent-two'], path: '/held', body: { book: first }, time: now })();
    assert.equal(forged.status, 401);
    // The token itself is never in what is sent.
    let sent = '';
    const watching = connectSealer({
      address: running.address,
      recorder: 'agent-one',
      token: tokens['agent-one'],
      clock: () => now,
      fetchImpl: async (url, init) => {
        sent += JSON.stringify(init.headers) + init.body.toString();
        return fetch(url, init);
      },
    });
    await watching.extend(first, 0, leaves, { line });
    assert.ok(!sent.includes(tokens['agent-one']));
    // The same question again (its number used once) is refused, and so is one with an old time.
    const once = question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/held', body: { book: first }, time: now });
    assert.equal((await once()).status, 200);
    assert.equal((await once()).status, 401);
    const late = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'], clock: () => now - 120000 });
    await assert.rejects(late.about(), /did not prove/);
    // A question dated at the far edge of the window is refused when sent again for as long as its time can be taken.
    const ahead = question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/held', body: { book: first }, time: now + QUESTION_WINDOW_MS });
    assert.equal((await ahead()).status, 200);
    now += 2 * QUESTION_WINDOW_MS;
    assert.equal((await ahead()).status, 401, 'sent again 120 seconds later, its time still in the window');
    // A number used once is 32 bytes (N2); a time is written in digits only (N7), whatever the proof covers.
    const short = await question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: now, nonce: toBase64url(nodeCrypto.randomBytes(16)) })();
    assert.equal(short.status, 401);
    const decimal = await question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: `${now}.0` })();
    assert.equal(decimal.status, 401);
    assert.equal((await question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: now })()).status, 200);
    // The first proof, checked before the body is read, covers the body's declared length, and must be there (L1).
    const askedFor = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: now, length: 3 });
    assert.equal((await fetch(`${running.address}/about`, { method: 'POST', headers: askedFor.headers, body: askedFor.bytes })).status, 401, 'a first proof over another length');
    const headless = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: now });
    delete headless.headers['provared-sealer-head'];
    assert.equal((await fetch(`${running.address}/about`, { method: 'POST', headers: headless.headers, body: headless.bytes })).status, 401, 'no first proof');
    const madeUp = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/about', time: now });
    madeUp.headers['provared-sealer-head'] = toBase64url(nodeCrypto.randomBytes(32));
    assert.equal((await fetch(`${running.address}/about`, { method: 'POST', headers: madeUp.headers, body: madeUp.bytes })).status, 401, 'a first proof made up');
    // Both proofs made with the token, and a body of the same length sent in place of the one the second proof covers.
    const swapped = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/held', body: { book: 'a' }, time: now });
    assert.equal((await fetch(`${running.address}/held`, { method: 'POST', headers: swapped.headers, body: Buffer.from(JSON.stringify({ book: 'b' })) })).status, 401, 'the second proof over another body');
    // A body larger than 8 MiB is not read.
    const status = await new Promise((done) => {
      const req = http.request(`${running.address}/extend`, { method: 'POST' }, (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', () => done('closed'));
      req.end(Buffer.alloc(9 * 1024 * 1024, 0x20));
    });
    assert.ok(status === 401 || status === 'closed', String(status));
  } finally {
    await running.close();
  }

  // A program that listens in the sealer's place, without the token, cannot make an answer a recorder takes.
  const impostor = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'provared-sealer-proof': toBase64url(new Uint8Array(32)) });
    res.end(JSON.stringify({ size: 99 }));
  });
  await new Promise((ok) => impostor.listen(0, '127.0.0.1', ok));
  try {
    const fooled = connectSealer({ address: `http://127.0.0.1:${impostor.address().port}`, recorder: 'agent-one', token: tokens['agent-one'] });
    await assert.rejects(fooled.held('x'), /did not prove that it comes from the sealer/);
  } finally {
    impostor.close();
  }
  // The proofs are HMAC-SHA-256 under the token: a check that they are not empty.
  assert.equal(sealerHmac(Buffer.alloc(32), 'x', 'y').length, 32);
});

test('one state holds every recorder\'s books, and a book belongs to the recorder that started it', async () => {
  const { folder, tokens } = await sealerFolder({}, ['agent-one', 'agent-two']);
  const running = await startSealer({ folder });
  try {
    const { lines, line, first, leaves } = await smallBook();
    const one = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const two = connectSealer({ address: running.address, recorder: 'agent-two', token: tokens['agent-two'] });
    await one.extend(first, 0, leaves, { line });
    const s1 = await one.seal(first, { previous: null });
    // The other recorder can do nothing with agent-one's book, nor with its first line.
    assert.equal(await two.held(first), null);
    assert.equal(await two.latest(first), null);
    assert.equal((await two.extend(first, 0, leaves.slice(0, 2), { line })).refused.code, 'other-recorder');
    assert.equal((await two.extend(first, 3, [await leafFingerprint(s1.line)])).refused.code, 'other-recorder');
    assert.equal((await two.seal(first, { previous: s1.fingerprint })).refused.code, 'other-recorder');
    assert.equal((await two.update(first, s1.entry, [])).refused.code, 'other-recorder');
    assert.equal((await two.extend({ first, number: 2 }, 0, [leaves[0]], { follows: first, line })).refused.code, 'other-recorder');
    // A book of its own, after agent-one's book: refused too.
    const other = (await permission('agent-two')).line;
    const fo = toBase64url(await leafFingerprint(other));
    assert.equal((await two.extend({ first: fo, number: 2 }, 0, [await leafFingerprint(other)], { follows: first, line: other })).refused.code, 'other-recorder');
    // Agent-one's book checks as it is.
    assert.deepEqual((await checkBook(lineOf([...lines, s1.line]), { sealKeys: [running.fingerprint] })).problems, []);
    // Its own book is its own; the state on the disk names each book's recorder.
    assert.equal((await two.extend(fo, 0, [await leafFingerprint(other)], { line: other })).size, 1);
    assert.deepEqual(onDisk(folder).books.map((b) => b.recorder).sort(), ['agent-one', 'agent-two']);
  } finally {
    await running.close();
  }
});

test('a recorder cannot start a book whose first line is a permission for another recorder\'s agent, nor bring one in after a fresh start (M1, L1)', async () => {
  const { folder, tokens } = await sealerFolder({}, ['agent-one', 'agent-two']);
  const files = sealerFiles(folder);
  // Agent one's book: its permission, a line, and a renewed permission for the same agent, then a line under it.
  const p1 = (await permission('agent-one', 'The first permission.')).line;
  const p2 = (await permission('agent-one', 'Renewed.')).line;
  const lines = [p1, '{"note":"one"}', p2, '{"note":"two"}'];
  const leaves = await Promise.all(lines.map(leafFingerprint));
  const P = toBase64url(leaves[0]);
  const P2 = toBase64url(leaves[2]);
  let running = await startSealer({ folder });
  let s1;
  try {
    const one = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const two = connectSealer({ address: running.address, recorder: 'agent-two', token: tokens['agent-two'] });
    await one.extend(P, 0, leaves, { line: p1 });
    s1 = await one.seal(P, { previous: null });
    // Agent two, with only its own token, starts no book from the renewed permission: it is agent one's agent's.
    assert.equal((await two.extend(P2, 0, leaves.slice(2), { line: p2 })).refused.code, 'other-recorder');
    assert.equal((await two.extend(P2, 0, leaves.slice(2))).refused.code, 'bad-field');
    // Agent one's next book starts with it, as a recorder does after a renewal.
    assert.deepEqual(await one.extend({ first: P2, number: 2 }, 0, [leaves[2]], { follows: P, line: p2 }), { size: 1 });
  } finally {
    await running.close();
  }
  // The state lost, and begun again with none: agent two cannot bring agent one's book in first.
  rmSync(files.state);
  running = await startSealer({ folder, fresh: true });
  try {
    const one = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const two = connectSealer({ address: running.address, recorder: 'agent-two', token: tokens['agent-two'] });
    assert.equal((await two.update(P, s1.entry, leaves, { line: p1 })).refused.code, 'other-recorder');
    assert.equal(await two.held(P), null);
    assert.deepEqual(await one.update(P, s1.entry, leaves, { line: p1 }), { size: 4 });
  } finally {
    await running.close();
  }
});

test('the list of recorders is read strictly: each agent belongs to one recorder, and their books add up to at most 1,000 (N5)', async () => {
  const { folder, tokens } = await sealerFolder();
  const files = sealerFiles(folder);
  const write = (recorders) => writeDurably(files.recorders, JSON.stringify({ recorders }));
  const entry = { token: tokens['agent-one'], agents: [await agentPrint('agent-one')] };
  const other = { token: toBase64url(nodeCrypto.randomBytes(32)), agents: [await agentPrint('agent-two')] };
  for (const [recorders, why] of [
    [{ 'Agent One': entry }, /not a recorder's name/],
    [{ 'agent-one': tokens['agent-one'] }, /must be an object/],
    [{ 'agent-one': { ...entry, agents: [] } }, /1 to 64 fingerprints/],
    [{ 'agent-one': { ...entry, agents: [entry.agents[0], entry.agents[0]] } }, /none twice/],
    [{ 'agent-one': { ...entry, books: 0 } }, /from 1 to 1,000/],
    [{ 'agent-one': { ...entry, note: 1 } }, /does not know/],
    [{ 'agent-one': entry, 'agent-two': { ...other, agents: entry.agents } }, /is named by the recorders "agent-one" and "agent-two"/],
    [{ 'agent-one': { ...entry, books: 600 }, 'agent-two': { ...other, books: 401 } }, /at most 1,000/],
  ]) {
    write(recorders);
    await refusedStart({ folder }, why);
  }
  write({ 'agent-one': { ...entry, books: 600 }, 'agent-two': { ...other, books: 400 } });
  await (await startSealer({ folder })).close();
  // Adding a recorder is held to the same rules.
  await assert.rejects(addRecorder(folder, 'agent-three', { agents: entry.agents }), /is named by the recorders "agent-one" and "agent-three"/);
  await assert.rejects(addRecorder(folder, 'agent-three', { agents: [await agentPrint('agent-three')] }), /at most 1,000/);
  await assert.rejects(addRecorder(folder, 'agent-three', {}), /must name in "agents"/);
  await assert.rejects(addRecorder(folder, 'agent-three', { agents: [await agentPrint('agent-three')], books: 0 }), /from 1 to 1,000/);
});

test('a recorder holds at most its number of books, and books with no seal are released while the sealer is stopped (M2)', async () => {
  const { folder, tokens } = await sealerFolder({}, ['agent-one', 'agent-two'], { 'agent-one': { books: 2 } });
  let running = await startSealer({ folder });
  const books = [];
  try {
    const one = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const two = connectSealer({ address: running.address, recorder: 'agent-two', token: tokens['agent-two'] });
    for (let i = 0; i < 3; i++) books.push(await smallBook());
    assert.deepEqual(await one.extend(books[0].first, 0, books[0].leaves, { line: books[0].line }), { size: 3 });
    assert.deepEqual(await one.extend(books[1].first, 0, books[1].leaves, { line: books[1].line }), { size: 3 });
    const third = await one.extend(books[2].first, 0, books[2].leaves, { line: books[2].line });
    assert.equal(third.refused.code, 'too-large');
    // The other recorder is not held back.
    const theirs = await smallBook('agent-two');
    assert.deepEqual(await two.extend(theirs.first, 0, theirs.leaves, { line: theirs.line }), { size: 3 });
    assert.ok((await one.seal(books[0].first, { previous: null })).entry);
    // Not while the sealer runs.
    await assert.rejects(releaseUnsealed(folder, 'agent-one'), /Another sealer/);
  } finally {
    await running.close();
  }
  // Agent one's book with no seal is released; its sealed book, and agent two's book, stay.
  const released = await releaseUnsealed(folder, 'agent-one');
  assert.deepEqual(released, [{ first: books[1].first, number: 1, recorder: 'agent-one' }]);
  assert.deepEqual(onDisk(folder).books.map((b) => [b.recorder, Boolean(b.latest)]), [['agent-one', true], ['agent-two', false]]);
  running = await startSealer({ folder });
  try {
    const one = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    assert.deepEqual(await one.extend(books[2].first, 0, books[2].leaves, { line: books[2].line }), { size: 3 });
  } finally {
    await running.close();
  }
  // The command, for every recorder.
  const run = spawnSync(process.execPath, [`--import=${LIBRARY_HOOK}`, '--disable-warning=ExperimentalWarning', BIN, 'release-unsealed', '--folder', folder], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /Released 2 books with no seal/);
  assert.deepEqual(onDisk(folder).books.map((b) => b.recorder), ['agent-one']);
});

test('bodies are read only for a question whose headers prove it, and at most 16 MiB at once for one recorder (L3, L1)', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  const opened = [];
  const partial = (headers, bytes, length) => sendPart(running.address, '/extend', headers, bytes, length, opened);
  // Headers shaped as a proof, made up by a program that holds no token.
  const shaped = (more = {}) => ({ 'provared-sealer-recorder': 'agent-one', 'provared-sealer-time': String(Date.now()), 'provared-sealer-nonce': toBase64url(nodeCrypto.randomBytes(32)), 'provared-sealer-head': toBase64url(nodeCrypto.randomBytes(32)), 'provared-sealer-proof': toBase64url(nodeCrypto.randomBytes(32)), ...more });
  // Headers that the recorder made with its token, for a body of "length" bytes (whose own proof is never sent whole).
  const headed = (length, more = {}) => ({ ...signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/extend', length, ...more }).headers });
  const MiB = 1024 * 1024;
  const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
  try {
    // A body of more than 8 MiB, sent with no declared length: its length is not proved, so it is not read.
    const chunked = await new Promise((done) => {
      const req = http.request(`${running.address}/extend`, { method: 'POST', headers: headed(9 * MiB) }, (res) => {
        res.resume();
        done(res.statusCode);
      });
      req.on('error', () => done('closed'));
      for (let i = 0; i < 9; i++) req.write(Buffer.alloc(MiB, 0x20));
      req.end();
    });
    assert.ok(chunked === 401 || chunked === 'closed', String(chunked));
    // No recorder this sealer serves, no well-formed proof, a time out of the window, a number used once already, or a
    // first proof that does not check: answered at once, the body never waited for.
    assert.equal(await within(partial({ 'provared-sealer-recorder': 'nobody' }, 1024, 4 * MiB), 5000), 401);
    assert.equal(await within(partial({ ...headed(4 * MiB), 'provared-sealer-proof': 'x' }, 1024, 4 * MiB), 5000), 401);
    assert.equal(await within(partial(headed(4 * MiB, { time: Date.now() - 10 * 60 * 1000 }), 1024, 4 * MiB), 5000), 401);
    const nonce = toBase64url(nodeCrypto.randomBytes(32));
    const taken = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/extend', nonce });
    assert.equal((await fetch(`${running.address}/extend`, { method: 'POST', headers: taken.headers, body: taken.bytes })).status, 200);
    assert.equal(await within(partial(headed(4 * MiB, { nonce }), 1024, 4 * MiB), 5000), 401);
    assert.equal(await within(partial(shaped(), 1024, 4 * MiB), 5000), 401, 'a first proof made up');
    assert.equal(await within(partial(headed(MiB), 1024, 4 * MiB), 5000), 401, 'a first proof over another length');
    // A body declared larger than 8 MiB, its headers proved: answered at once.
    assert.equal(await within(partial(headed(9 * MiB), 1024, 9 * MiB), 5000), 413);
    // A program with no token cannot have bodies held under a recorder's name (L1): each is answered at once, and the
    // recorder is answered meanwhile. A client still sending when the answer comes may see the connection closed instead.
    const squatting = [1, 2, 3].map(() => within(partial(shaped(), 8 * MiB - 1, 8 * MiB), 5000));
    await pause(300);
    assert.equal(await client.held('x'.repeat(1000)), null);
    for (const status of await Promise.all(squatting)) assert.ok(status === 401 || status === 'closed', String(status));
    // Two bodies of 8 MiB being read for the recorder itself: a third is turned away (busy), unproved.
    partial(headed(8 * MiB), 8 * MiB - 1, 8 * MiB);
    partial(headed(8 * MiB), 8 * MiB - 1, 8 * MiB);
    await pause(1500);
    assert.equal(await within(partial(headed(MiB), 64 * 1024, MiB), 5000), 503);
    for (const req of opened) req.destroy();
    // Once they are gone, what they held is let go, and the recorder is answered again. The question is of 2 MiB,
    // so that it is answered only where what they held was let go, not because it fits in bytes that never arrived (P10d).
    await pause(500);
    assert.equal(await client.held('x'.repeat(2 * MiB)), null);
  } finally {
    for (const req of opened) req.destroy();
    await running.close();
  }
});

test('each recorder keeps its own numbers used once; a busy answer is proved and keeps no number; the clock never goes back (L4, N4, N12)', async () => {
  let now = Date.now();
  const { folder, tokens } = await sealerFolder({}, ['agent-one', 'agent-two']);
  const running = await startSealer({ folder, clock: () => now, maxNonces: 2 });
  const ask = (name, more = {}) => question({ address: running.address, recorder: name, key: tokens[name], path: '/about', time: now, ...more });
  const opened = [];
  try {
    // One question sent twice at once: the copy whose body ends first is taken, and the other is refused, though both
    // were checked before either was taken.
    const twice = signed({ recorder: 'agent-two', key: tokens['agent-two'], path: '/about', time: now });
    const slow = sendPart(running.address, '/about', twice.headers, twice.bytes.subarray(0, 1), twice.bytes.length, opened);
    await pause(300);
    assert.equal((await fetch(`${running.address}/about`, { method: 'POST', headers: twice.headers, body: twice.bytes })).status, 200);
    opened[0].end(twice.bytes.subarray(1));
    assert.equal(await within(slow, 5000), 401);
    const t0 = now;
    assert.equal((await ask('agent-one')()).status, 200);
    assert.equal((await ask('agent-one')()).status, 200);
    // Agent one's share is full: its next question is turned away, with a proof, and its number is not kept.
    now = t0 + QUESTION_WINDOW_MS;
    const third = ask('agent-one');
    const busy = await third();
    assert.equal(busy.status, 503);
    assert.equal((await busy.json()).refused.code, 'busy');
    assert.ok(busy.headers.get('provared-sealer-proof'), 'a busy answer to a proved question is proved');
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'], clock: () => now });
    await assert.rejects(client.about(), (e) => e.code === 'busy' && e.status === 503);
    // Agent two's share is its own.
    assert.equal((await ask('agent-two')()).status, 200);
    // The numbers are forgotten once their questions could no longer be taken; the one turned away was never kept, so
    // sent again while its time can still be taken, it is taken, once.
    now = t0 + QUESTION_WINDOW_MS + 2;
    assert.equal((await third()).status, 200);
    assert.equal((await third()).status, 401, 'kept once taken');
    // The clock set back: a question from before is not taken again, though its number was forgotten; nor is any
    // question dated more than the window before the latest time the clock gave, until the clock is there again.
    const at = now;
    const kept = question({ address: running.address, recorder: 'agent-two', key: tokens['agent-two'], path: '/about', time: at });
    assert.equal((await kept()).status, 200);
    now = at + 2 * QUESTION_WINDOW_MS + 5;
    assert.equal((await ask('agent-two')()).status, 200);
    now = at;
    assert.equal((await kept()).status, 401, 'taken again after the clock went back');
    assert.equal((await ask('agent-two')()).status, 401);
    now = at + 2 * QUESTION_WINDOW_MS + 5;
    assert.equal((await ask('agent-two')()).status, 200);
    // A question whose body arrives after its time has left the window is refused when the body has been read.
    const slowly = signed({ recorder: 'agent-two', key: tokens['agent-two'], path: '/about', time: now });
    const lateBody = sendPart(running.address, '/about', slowly.headers, slowly.bytes.subarray(0, 1), slowly.bytes.length, opened);
    await pause(300);
    now += 2 * QUESTION_WINDOW_MS + 5;
    opened.at(-1).end(slowly.bytes.subarray(1));
    assert.equal(await within(lateBody, 5000), 401);
  } finally {
    for (const req of opened) req.destroy();
    await running.close();
  }
  // An answer of 503 that carries no proof (a sealer that held too many bodies) reads as busy, and nothing in it is used.
  const turnedAway = http.createServer((req, res) => {
    res.writeHead(503, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ size: 99 }));
  });
  await new Promise((ok) => turnedAway.listen(0, '127.0.0.1', ok));
  try {
    const c = connectSealer({ address: `http://127.0.0.1:${turnedAway.address().port}`, recorder: 'agent-one', token: tokens['agent-one'] });
    await assert.rejects(c.about(), (e) => e.code === 'busy' && e.status === 503 && /Nothing it says is used/.test(e.message));
  } finally {
    turnedAway.close();
  }
});

test('a recorder connects only to http://127.0.0.1:<port> (N6)', async () => {
  const token = toBase64url(nodeCrypto.randomBytes(32));
  for (const address of ['http://localhost:8797', 'http://127.0.0.1', 'http://127.0.0.1:0', 'https://127.0.0.1:8797', 'http://127.0.0.1:8797/', 'http://127.0.0.10:8797', 'http://[::1]:8797']) {
    assert.throws(() => connectSealer({ address, recorder: 'agent-one', token }), /must be http:\/\/127\.0\.0\.1:<port>/, address);
  }
  assert.doesNotThrow(() => connectSealer({ address: 'http://127.0.0.1:8797', recorder: 'agent-one', token }));
});

test('a sealer put back from an older state is brought up to date, and the update is saved before the answer', async () => {
  const { folder, tokens } = await sealerFolder();
  const files = sealerFiles(folder);
  const lines = [(await permission()).line, ...Array.from({ length: 3 }, (_, i) => JSON.stringify({ u: i }))];
  const first = toBase64url(await leafFingerprint(lines[0]));
  let running = await startSealer({ folder });
  let s1;
  let s2;
  let between;
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    await client.extend(first, 0, await Promise.all(lines.map(leafFingerprint)), { line: lines[0] });
    s1 = await client.seal(first, { previous: null });
  } finally {
    await running.close();
  }
  const older = readFileSync(files.state, 'utf8');
  running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    between = [s1.line, '{"u":4}'];
    await client.extend(first, 4, await Promise.all(between.map(leafFingerprint)));
    s2 = await client.seal(first, { previous: s1.fingerprint });
  } finally {
    await running.close();
  }
  writeDurably(files.state, older);
  running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    assert.equal((await client.seal(first, { previous: s2.fingerprint })).refused.code, 'not-up-to-date');
    // An entry longer than a line of a book may be is refused, and the state is not swollen by it (Md1).
    const sizeBefore = readFileSync(files.state).length;
    const swollen = { ...s2.entry, stamps: Array.from({ length: 64 }, () => 'A'.repeat(100000)) };
    assert.equal((await client.update(first, swollen, await Promise.all(between.map(leafFingerprint)))).refused.code, 'too-large');
    assert.equal(readFileSync(files.state).length, sizeBefore);
    // The entry as the book holds it, with witness statements: taken, and only the seal is kept.
    assert.deepEqual(await client.update(first, { ...s2.entry, witnesses: [{ any: 'thing' }] }, await Promise.all(between.map(leafFingerprint))), { size: 6 });
    // Saved before the answer was given.
    assert.equal(onDisk(folder).books[0].latest.entry.seal.payload, s2.entry.seal.payload);
    assert.deepEqual(Object.keys(onDisk(folder).books[0].latest.entry), ['seal']);
  } finally {
    await running.close();
  }
});

// A sealer whose seals wait for their time-stamp until the test lets them go: once "heldQueue" gives it back, the seal
// asked for holds the queue, so nothing in a test depends on which question reaches the sealer first (T1).
async function heldQueue(more = {}) {
  const { folder, tokens } = await sealerFolder();
  let letGo;
  const gate = new Promise((ok) => {
    letGo = ok;
  });
  let holding;
  const held = new Promise((ok) => {
    holding = ok;
  });
  const running = await startSealer({
    folder,
    ...more,
    stamp: async () => {
      holding();
      await gate;
      return undefined;
    },
  });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const { line, first, leaves } = await smallBook();
    assert.deepEqual(await client.extend(first, 0, leaves, { line }), { size: 3 });
    const sealing = client.seal(first, { previous: null });
    // The seal holds the queue once the hook is called; a seal answered first (refused, say) fails the test at once
    // rather than leaving it waiting.
    const came = await Promise.race([held.then(() => 'held'), sealing.then((v) => ({ v }), (e) => ({ e }))]);
    if (came !== 'held') throw new Error(`The seal was answered before it held the queue: ${JSON.stringify(came.v?.refused ?? String(came.e))}`);
    return { folder, tokens, running, client, first, sealing, letGo };
  } catch (e) {
    letGo();
    await running.close();
    throw e;
  }
}

// The garbage collector, reached without a flag on the command line; the heap measured after it has run.
v8.setFlagsFromString('--expose-gc');
const collect = runInNewContext('gc');
const heapUsed = () => {
  collect();
  collect();
  return process.memoryUsage().heapUsed;
};

// The test waits for events, not for a length of time: the seal is let go only once the sealer has read all 16
// questions whole and decided on each, so every one of them was decided while the seal held the queue.
test('one recorder may have at most 16 questions waiting (T1)', async () => {
  const { running, client, first, sealing, letGo } = await heldQueue();
  const emit = http.Server.prototype.emit;
  try {
    // The sealer decides on a question (it waits, or it is turned away) in its own handler for the end of the body,
    // with nothing awaited before the decision; a handler added after the sealer's runs after it.
    let decided = 0;
    let allDecided;
    const everyOne = new Promise((ok) => {
      allDecided = ok;
    });
    http.Server.prototype.emit = function (...args) {
      const handled = emit.apply(this, args);
      const [event, req] = args;
      if (event === 'request' && req.url === '/held') {
        req.once('end', () => {
          if (++decided === 16) allDecided();
        });
      }
      return handled;
    };
    // The seal holds the queue and counts as one of the 16: of 16 more questions, 15 wait and one is turned away at
    // once, whatever order they arrive in.
    const asked = Array.from({ length: 16 }, () =>
      client.held(first).then(
        (value) => ({ value }),
        (reason) => ({ reason }),
      ),
    );
    assert.notEqual(await within(everyOne, 60000), 'no answer', 'Waited a minute and the sealer had not decided on all 16 questions.');
    // Let go: the 15 that waited are answered in their turn, and no other was turned away.
    letGo();
    assert.ok((await sealing).entry, 'the seal');
    const answers = await Promise.all(asked);
    const turnedAway = answers.filter((a) => a.reason);
    assert.equal(turnedAway.length, 1, JSON.stringify(answers.map((a) => a.reason?.code ?? a.value?.size)));
    assert.equal(turnedAway[0].reason.code, 'busy', String(turnedAway[0].reason));
    assert.equal(turnedAway[0].reason.status, 503);
    for (const a of answers) if (!a.reason) assert.equal(a.value.size, 3);
  } finally {
    http.Server.prototype.emit = emit;
    letGo();
    await running.close();
  }
});

test('a body that is not JSON keeps its number used once; a body waits as its bytes, its read form not held while it waits (K19, K21)', async () => {
  const { tokens, running, first, sealing, letGo } = await heldQueue();
  const send = (q, path = '/held') => fetch(`${running.address}${path}`, { method: 'POST', headers: q.headers, body: q.bytes });
  try {
    // A body of about 4 MiB that reads as about 1.4 million empty objects: it waits as its bytes only, which are not
    // on the heap. Read before its turn and kept, its read form would take tens of megabytes of the heap (K21).
    const pad = Buffer.from(`{"book":"${first}","pad":[${'{},'.repeat(1400000)}{}]}`);
    const before = heapUsed();
    const waiting = send(signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/held', raw: pad }));
    await pause(2500);
    const grown = heapUsed() - before;
    assert.ok(grown < 16 * 1024 * 1024, `the heap grew by ${Math.round(grown / 1048576)} MB while the body waited`);
    letGo();
    assert.ok((await sealing).entry, 'the seal');
    const answered = await waiting;
    assert.equal(answered.status, 200);
    assert.equal((await answered.json()).refused.code, 'bad-field', 'read in its turn: "pad" is not a member /held takes');
    // A body that is not JSON is refused in its turn, and its number stays used: the same question is not taken again.
    const notJson = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/held', raw: Buffer.from('not json') });
    const refused = await send(notJson);
    assert.equal(refused.status, 400);
    assert.equal((await refused.json()).refused.code, 'bad-field');
    assert.equal((await send(notJson)).status, 401, 'the number used once by a body that is not JSON is kept');
  } finally {
    letGo();
    await running.close();
  }
});

test('a body that ends after it was turned away while being read is not answered twice (K9)', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  const opened = [];
  const MiB = 1024 * 1024;
  const failures = [];
  const noted = (e) => failures.push(e);
  process.on('unhandledRejection', noted);
  process.on('uncaughtException', noted);
  // The bytes of /extend bodies the sealer has read, counted by a handler added after its own, so that it has
  // counted them already: the small questions are sent only once all of both part-bodies have arrived.
  const emit = http.Server.prototype.emit;
  let read = 0;
  let allRead;
  const bothRead = new Promise((ok) => {
    allRead = ok;
  });
  http.Server.prototype.emit = function (...args) {
    const handled = emit.apply(this, args);
    const [event, req] = args;
    if (event === 'request' && req.url === '/extend') {
      req.on('data', (chunk) => {
        read += chunk.length;
        if (read >= 2 * (8 * MiB - 1)) allRead();
      });
    }
    return handled;
  };
  try {
    const headed = (length) => signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/extend', length }).headers;
    // Two bodies of 8 MiB being read hold the recorder's 16 MiB.
    sendPart(running.address, '/extend', headed(8 * MiB), 8 * MiB - 1, 8 * MiB, opened);
    sendPart(running.address, '/extend', headed(8 * MiB), 8 * MiB - 1, 8 * MiB, opened);
    assert.notEqual(await within(bothRead, 60000), 'no answer', 'Waited a minute and the sealer had not read both part-bodies.');
    http.Server.prototype.emit = emit;
    // A small question sent whole, in one piece: turned away while its body is read, and its body then ends at once.
    for (let i = 0; i < 5; i++) {
      const q = signed({ recorder: 'agent-one', key: tokens['agent-one'], path: '/held', body: { book: 'x'.repeat(1000) } });
      const status = await within(
        new Promise((done) => {
          const req = http.request(`${running.address}/held`, { method: 'POST', headers: { ...q.headers, 'content-length': String(q.bytes.length) } }, (res) => {
            res.resume();
            done(res.statusCode);
          });
          req.on('error', () => done('closed'));
          req.end(q.bytes);
        }),
        5000,
      );
      assert.ok(status === 503 || status === 'closed', String(status));
    }
    await pause(500);
    assert.deepEqual(failures.map((e) => e?.code ?? String(e)), [], 'nothing was answered a second time');
  } finally {
    http.Server.prototype.emit = emit;
    process.off('unhandledRejection', noted);
    process.off('uncaughtException', noted);
    for (const req of opened) req.destroy();
    await running.close();
  }
});

test('a question\'s body may hold only the members its path takes (L1)', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const { line, first, leaves } = await smallBook();
    const ask = async (path, body) => (await question({ address: running.address, recorder: 'agent-one', key: tokens['agent-one'], path, body })()).json();
    const refusedFor = async (path, body) => {
      const got = await ask(path, body);
      assert.equal(got.refused?.code, 'bad-field', `${path} ${JSON.stringify(Object.keys(body))}`);
      assert.match(got.refused.message, /does not take\. It takes/);
    };
    // A book not yet started, with its first line misspelt: refused for that member, not for a missing line.
    await refusedFor('/extend', { book: first, at: 0, leaves: leaves.map(toBase64url), lines: line });
    assert.equal(await client.held(first), null, 'nothing was taken');
    assert.deepEqual(await client.extend(first, 0, leaves, { line }), { size: 3 });
    await refusedFor('/extend', { book: first, at: 3, leaves: [], folows: first });
    await refusedFor('/seal', { book: first, previous: null, id: toBase64url(nodeCrypto.randomBytes(16)) });
    await refusedFor('/update', { book: first, entry: {}, leaves: [], lines: line });
    await refusedFor('/latest', { book: first, number: 1 });
    await refusedFor('/held', { book: first, note: 1 });
    await refusedFor('/about', { note: 1 });
    await refusedFor('/held', JSON.parse(`{"book":"${first}","__proto__":{}}`));
    // A body that is not a JSON object is refused on every path, /about among them, which takes no member (K80).
    for (const path of ['/about', '/held', '/latest', '/extend', '/seal', '/update']) {
      for (const body of [[], null, 5, 'x', true, [first]]) {
        const got = await ask(path, body);
        assert.equal(got.refused?.code, 'bad-field', `${path} ${JSON.stringify(body)}`);
        assert.equal(got.refused.message, 'The body must be a JSON object.', `${path} ${JSON.stringify(body)}`);
      }
    }
    assert.equal((await client.held(first)).size, 3, 'nothing was taken');
    // The same questions with only the members their paths take are answered.
    assert.equal((await ask('/held', { book: first })).held.size, 3);
    assert.equal((await ask('/about', {})).sealer, running.fingerprint);
    assert.equal((await ask('/latest', { book: first })).latest, null);
    assert.equal((await ask('/extend', { book: first, at: 3, leaves: [] })).size, 3);
  } finally {
    await running.close();
  }
});

test('a recorder\'s "more" cannot replace the members of its call, "id" is refused before it travels, and a Date is sent as its milliseconds (K77, K78)', async () => {
  const { folder, tokens } = await sealerFolder();
  const running = await startSealer({ folder });
  try {
    let sent = 0;
    const counting = (...args) => {
      sent++;
      return fetch(...args);
    };
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'], fetchImpl: counting });
    const { line, first, leaves } = await smallBook();
    const other = await smallBook();
    assert.deepEqual(await client.extend(first, 0, leaves, { line }), { size: 3 });
    const one = await leafFingerprint('{"note":"three"}');
    const before = sent;
    const refusedHere = (got, what, pattern = /^more: holds a member that a question to \/[a-z]+ does not take/) => {
      assert.equal(got.refused?.code, 'bad-field', `${what}: ${JSON.stringify(got)}`);
      assert.match(got.refused.message, pattern, what);
    };
    // A member of "more" that names a member of the call itself, or any the path does not take: refused, nothing sent.
    refusedHere(await client.extend(first, 3, [], { leaves: [toBase64url(one)] }), 'extend, leaves in more');
    refusedHere(await client.extend(first, 0, [one], { at: 3 }), 'extend, at in more');
    refusedHere(await client.extend(first, 3, [one], { book: other.first }), 'extend, book in more');
    refusedHere(await client.extend(first, 3, [one], { lines: line }), 'extend, a misspelt member');
    refusedHere(await client.update(first, { seal: {} }, [], { entry: { seal: {} } }), 'update, entry in more');
    refusedHere(await client.update(first, { seal: {} }, [], { leaves: [] }), 'update, leaves in more');
    refusedHere(await client.update(first, { seal: {} }, [], { follows: first }), 'update, follows');
    refusedHere(await client.seal(first, { previous: null, book: other.first }), 'seal, book in more');
    refusedHere(await client.seal(first, { previous: null, id: toBase64url(nodeCrypto.randomBytes(16)) }), 'seal, id', /does not take \("id": the sealer makes the seal's id itself\)\. It takes previous, when\./);
    refusedHere(await client.seal(first, {}), 'seal, no previous', /^more: "previous" is missing\.$/);
    refusedHere(await client.seal(first, null), 'seal, more null', /^more: must be an object\.$/);
    refusedHere(await client.extend(first, 3, [one], []), 'extend, more a list', /^more: must be an object\.$/);
    assert.equal(sent, before, 'none of these was sent');
    assert.equal((await client.held(first)).size, 3, 'nothing was taken');
    // What "more" may hold is still taken.
    assert.deepEqual(await client.extend(first, 3, [one], {}), { size: 4 });
    // A time given as a Date is sent as its milliseconds, as the library takes a Date, and the seal is dated by it.
    const at = Date.now() - 60 * 1000;
    const sealed = await client.seal(first, { previous: null, when: new Date(at) });
    assert.ok(sealed.entry, JSON.stringify(sealed.refused));
    assert.equal(JSON.parse(Buffer.from(sealed.entry.seal.payload, 'base64url').toString('utf8')).when, formatTime(at));
  } finally {
    await running.close();
  }
});

test('a body waits as its bytes only, is turned away by the waiting limits before it is read as JSON, and is read in its turn (Md2)', async () => {
  assert.equal(MAX_WAITING_BYTES, 32 * 1024 * 1024);
  const { folder, tokens } = await sealerFolder();
  let letGo;
  const gate = new Promise((ok) => {
    letGo = ok;
  });
  let stamping = 0;
  // A seal holds the queue for as long as the test likes: it waits for its time-stamp.
  const running = await startSealer({
    folder,
    maxWaitingBytes: 64 * 1024,
    stamp: async () => {
      stamping++;
      await gate;
      return undefined;
    },
  });
  const send = (path, more = {}) => {
    const q = signed({ recorder: 'agent-one', key: tokens['agent-one'], path, ...more });
    return fetch(`${running.address}${path}`, { method: 'POST', headers: q.headers, body: q.bytes });
  };
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const { line, first, leaves } = await smallBook();
    assert.deepEqual(await client.extend(first, 0, leaves, { line }), { size: 3 });
    const sealing = client.seal(first, { previous: null });
    // Wait for the seal to hold the queue; a seal answered first fails the test rather than leaving it waiting.
    let answered = false;
    sealing.then(
      () => (answered = true),
      () => (answered = true),
    );
    // eslint-disable-next-line no-unmodified-loop-condition -- both are set by callbacks that run while the loop waits.
    while (stamping === 0 && !answered) await pause(50);
    assert.equal(stamping, 1, 'the seal holds the queue');
    // A body that is not JSON waits for its turn unread: no answer while the seal holds the queue.
    const notJson = send('/held', { raw: Buffer.from('not json') });
    assert.equal(await within(notJson, 700), 'no answer', 'read as JSON before its turn');
    // The bytes waiting for one recorder are limited (64 KiB here): two bodies of about 25,000 bytes wait; a third is
    // turned away (busy), with a proof.
    const padded = () => send('/held', { body: { book: first, pad: 'x'.repeat(25000) } });
    const waiting = [padded(), padded()];
    await pause(500);
    const third = await within(padded(), 3000);
    assert.equal(third.status, 503);
    assert.equal((await third.json()).refused.code, 'busy');
    assert.ok(third.headers.get('provared-sealer-proof'), 'a busy answer to a proved question is proved');
    // The limit of 16 waiting comes before the body is read as JSON: with 16 waiting, a body that is not JSON is turned
    // away as busy, not refused as not JSON.
    const filled = Array.from({ length: 12 }, () => send('/about'));
    await pause(700);
    const over = await within(send('/held', { raw: Buffer.from('not json either') }), 3000);
    assert.equal(over.status, 503);
    assert.equal((await over.json()).refused.code, 'busy');
    // The seal let go: every question waiting is answered in its turn, and the one that is not JSON is refused then.
    letGo();
    assert.ok((await sealing).entry, 'the seal');
    const refused = await notJson;
    assert.equal(refused.status, 400);
    assert.equal((await refused.json()).refused.code, 'bad-field');
    for (const r of [...(await Promise.all(waiting)), ...(await Promise.all(filled))]) assert.equal(r.status, 200);
    // What waited is let go: the recorder's bytes and places are free again.
    assert.equal((await padded()).status, 200);
    assert.equal((await send('/about')).status, 200);
  } finally {
    letGo();
    await running.close();
  }
  await refusedStart({ folder: tempFolder(), maxWaitingBytes: 0 }, /"maxWaitingBytes" must be a whole number/);
});

test('a start refuses a missing state unless told to begin it again, and a second sealer on the same folder', async () => {
  const { folder } = await sealerFolder();
  const files = sealerFiles(folder);
  const running = await startSealer({ folder });
  try {
    await refusedStart({ folder }, /Another sealer/);
  } finally {
    // Closed whatever happens, so that a failure here fails the test and never leaves it waiting.
    await running.close();
  }
  // --fresh begins only a state that is missing.
  await refusedStart({ folder, fresh: true }, /begins only a state that is missing/);
  rmSync(files.state);
  await refusedStart({ folder }, /is missing/);
  // A recorder is not added while the state is missing.
  await assert.rejects(addRecorder(folder, 'agent-two', { agents: [await agentPrint('agent-two')] }), /is missing, though there are recorders/);
  const fresh = await startSealer({ folder, fresh: true });
  await fresh.close();
  assert.deepEqual(onDisk(folder).books, []);
  // A lock left by a process that has ended is taken over; so is one that names no process (N13).
  writeDurably(files.lock, '999999');
  const after = await startSealer({ folder });
  await after.close();
  for (const left of ['0', 'not a number']) {
    writeDurably(files.lock, left);
    await (await startSealer({ folder })).close();
  }
});

test('a new recorder never takes over the books of an old one of the same name', async () => {
  const { folder, tokens } = await sealerFolder();
  const files = sealerFiles(folder);
  const running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token: tokens['agent-one'] });
    const { line, first, leaves } = await smallBook();
    await client.extend(first, 0, leaves, { line });
  } finally {
    await running.close();
  }
  // The recorder is taken off the list by hand; its books stay in the state.
  writeDurably(files.recorders, JSON.stringify({ recorders: {} }));
  await assert.rejects(addRecorder(folder, 'agent-one', { agents: [await agentPrint('agent-one')] }), /never taken over/);
  assert.match(await addRecorder(folder, 'agent-two', { agents: [await agentPrint('agent-two')] }), /^[A-Za-z0-9_-]{43}$/);
});

test('a signer module named in the settings takes the place of the key file\'s key for its method', async () => {
  const folder = tempFolder();
  writeFileSync(
    join(folder, 'ed-signer.mjs'),
    [
      "import { signerFromKey } from 'provared';",
      '// One key for as long as the program runs: a stand-in for a key held in a key service.',
      "const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);",
      "const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);",
      'export default async function ({ alg }) {',
      "  return signerFromKey(alg, pair.privateKey, { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: jwk.x });",
      '}',
      '',
    ].join('\n'),
  );
  writeFileSync(join(folder, 'sealer.json'), JSON.stringify({ name: 'Example central sealer (invented)', port: 0, signers: { Ed25519: './ed-signer.mjs' } }));
  await makeKeys(folder);
  const held = JSON.parse(readFileSync(sealerFiles(folder).keys, 'utf8')).keys;
  assert.deepEqual(held.map((k) => k.alg), ['ML-DSA-87', 'SLH-DSA-SHA2-256s']);
  const token = await addRecorder(folder, 'agent-one', { agents: [await agentPrint('agent-one')] });
  const running = await startSealer({ folder });
  try {
    const client = connectSealer({ address: running.address, recorder: 'agent-one', token });
    const { lines, line, first, leaves } = await smallBook();
    await client.extend(first, 0, leaves, { line });
    const s = await client.seal(first, { previous: null });
    assert.deepEqual((await checkBook(lineOf([...lines, s.line]), { sealKeys: [running.fingerprint] })).problems, []);
    assert.equal(running.by.keys[0].alg, 'Ed25519');
  } finally {
    await running.close();
  }
});

test('the command: init, keys, add-recorder and release-unsealed', async () => {
  const folder = tempFolder();
  const run = (...args) => spawnSync(process.execPath, [`--import=${LIBRARY_HOOK}`, '--disable-warning=ExperimentalWarning', BIN, ...args], { encoding: 'utf8' });
  assert.equal(run('init', '--folder', folder).status, 2, 'init needs a name the first time');
  const init = run('init', '--folder', folder, '--name', 'Example central sealer (invented)');
  assert.equal(init.status, 0, init.stderr);
  assert.match(init.stdout, /Made the key file/);
  assert.match(init.stdout, /Key set: +[A-Za-z0-9_-]{43}/);
  const again = run('init', '--folder', folder);
  assert.match(again.stdout, /was not changed/);
  const agent = await agentPrint('agent-one');
  const noAgent = run('add-recorder', '--folder', folder, 'agent-one');
  assert.equal(noAgent.status, 2);
  assert.match(noAgent.stderr, /at least one --agent/);
  const added = run('add-recorder', '--folder', folder, '--agent', agent, '--books', '5', 'agent-one');
  assert.equal(added.status, 0, added.stderr);
  assert.match(added.stdout, /\n[A-Za-z0-9_-]{43}\n/);
  const listed = JSON.parse(readFileSync(sealerFiles(folder).recorders, 'utf8')).recorders['agent-one'];
  assert.deepEqual([listed.agents, listed.books], [[agent], 5]);
  assert.equal(run('add-recorder', '--folder', folder, '--agent', agent, 'agent-one').status, 2);
  assert.equal(run('add-recorder', '--folder', folder, '--agent', await agentPrint('agent-two'), 'Agent One').status, 2);
  assert.equal(run('add-recorder', '--folder', folder, '--agent', agent, 'agent-two').status, 2, 'an agent belongs to one recorder');
  assert.equal(run('add-recorder', '--folder', folder, '--agent', await agentPrint('agent-two'), '--books', 'x', 'agent-two').status, 2);
  assert.equal(run('keys', '--folder', folder, '--agent', agent).status, 2, '--agent belongs to add-recorder');
  assert.equal(run('start', '--folder', folder, '--fresh', '--fresh').status, 2, '--fresh is given once');
  const released = run('release-unsealed', '--folder', folder, 'agent-one');
  assert.equal(released.status, 0, released.stderr);
  assert.match(released.stdout, /Released 0 books with no seal of the recorder "agent-one"/);
  assert.equal(run('release-unsealed', '--folder', folder, 'a', 'b').status, 2);
  assert.equal(run('keys', '--folder', folder).status, 0);
  assert.equal(run('nonsense', '--folder', folder).status, 2);
  assert.equal(run('--help').status, 0);
});
