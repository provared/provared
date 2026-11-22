// Taking a first permission in the waiting recorder (POST /admit, after the
// person typed the thumbprint and "yes" on this computer), and the switch
// to the full recorder on the same port and feed. One admit at a time; the
// checks before anything is written; the list of trusted passkeys written
// as exactly this one passkey; the full recorder built and put in place in
// one step, with nothing closed and nothing listening again; "taken" only
// once the full recorder answers. A start that fails puts back what it
// wrote, and the permission waits. Every test works in a temporary folder
// and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

const { assembleCancellation, prepareCancellation, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { feedReader } = await import('../feed.mjs');
const { admitWaiting, readTrusted, readWaitingPermissions } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, runCommand, runHook, signSlip, status, tempFolder } = await import('./world.mjs');

const LOCAL = { signingOrigins: ['http://localhost'] };
const read = (folder, name) => readFileSync(join(folder, name), 'utf8');

/** A promise, or a failure once "ms" have passed without it (measured on the monotonic clock by the timer). */
const within = (promise, ms, what) => Promise.race([promise, new Promise((resolve, reject) => setTimeout(() => reject(new Error(`${what}: not within ${ms} ms`)), ms).unref())]);

/** A gate a test opens: "faults" waits at the step named until it is opened. */
function gateAt(step) {
  let open;
  let reached;
  const opened = new Promise((r) => (open = r));
  const reachedIt = new Promise((r) => (reached = r));
  return { open, reached: reachedIt, faults: async (at) => { if (at === step) { reached(); await opened; } } };
}

async function waitingWorld(more = {}) {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, ...LOCAL, ...more });
  const reader = feedReader({ address: `http://127.0.0.1:${waiting.port}`, token: read(w.folder, 'feed-token').trim() });
  /** A permission signed by "passkey" (the person's, by default), handed over and waiting. */
  const handed = async (passkey = w.passkey, purpose = 'The first permission.') => {
    const slip = await signSlip({ agentKeys: w.agent.keys, passkey, purpose });
    const said = (await reader.post('/hand-over', { kind: 'renewal', slip })).body;
    assert.equal(said.code, 'waits-for-yes', JSON.stringify(said));
    return { slip, fp: said.fingerprint, T: said.thumbprint };
  };
  return { ...w, waiting, port: waiting.port, reader, handed };
}

test('after "yes", the waiting recorder takes the permission: the book\'s first line is the slip, the trusted list is this one passkey, "taken" comes once /status names the slip, and a call inside it is allowed', async () => {
  const w = await waitingWorld();
  try {
    const mine = await w.handed();
    assert.equal(mine.T, await thumbprint(w.passkey.key));
    const said = [];
    const code = await admitWaiting(w.folder, w.port, mine.T.slice(0, 16), { answer: async () => 'yes', terminal: true, say: (words) => said.push(words) });
    assert.equal(code, 0, said.join('\n'));
    // At once: the full recorder answers on the same port, under the slip.
    const st = await status(w.port);
    assert.equal(st.waiting, undefined, 'no longer waiting');
    assert.equal(st.slip, mine.fp);
    assert.equal(st.issuer, mine.T);
    assert.deepEqual(readTrusted(w.folder), [mine.T]);
    const book = read(w.folder, 'book.jsonl').split('\n').filter(Boolean);
    assert.equal(book.length, 1);
    assert.deepEqual(JSON.parse(book[0]), { slip: mine.slip });
    assert.deepEqual(JSON.parse(read(w.folder, 'slip.json')), mine.slip);
    assert.equal(readWaitingPermissions(w.folder).length, 0, 'it no longer waits');
    const pre = await runHook(w.port, 'PreToolUse', 'Read', { file_path: 'README.md' });
    assert.equal(pre.out, '', 'a call inside the permission is allowed');
    // The feed is the same: its reader's conversation holds, and it lists the book now.
    const books = await w.reader.get('/books');
    assert.equal(books.proved, true);
    assert.equal(books.body.books.length, 1);
  } finally {
    await w.waiting.close();
  }
});

test('the taken answer comes only after the full recorder is in place: asked directly, /status names the slip the moment "taken" arrives', async () => {
  const w = await waitingWorld();
  try {
    const mine = await w.handed();
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.proved, true);
    assert.equal(r.body.outcome, 'taken', JSON.stringify(r.body));
    assert.equal((await status(w.port)).slip, mine.fp);
  } finally {
    await w.waiting.close();
  }
});

test('two admits at once: one is taken, the other answered "busy", and one passkey alone is trusted', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  try {
    const mine = await w.handed();
    const other = await w.handed(await developmentPasskey(), 'Another passkey\'s.');
    const first = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the first admit at its checks');
    const second = await feedReader({ address: `http://127.0.0.1:${w.port}`, token: read(w.folder, 'feed-token').trim() }).post('/admit', { fingerprint: other.fp, thumbprint: other.T, take: true });
    assert.equal(second.code, 409, JSON.stringify(second.body));
    assert.equal(second.body.code, 'busy');
    assert.equal(existsSync(join(w.folder, 'trusted-passkeys.json')), false, 'nothing is written while the first waits');
    gate.open();
    const took = await within(first, 30000, 'the first admit');
    assert.equal(took.body.outcome, 'taken', JSON.stringify(took.body));
    assert.deepEqual(readTrusted(w.folder), [mine.T], 'one passkey alone is trusted');
    assert.deepEqual(readWaitingPermissions(w.folder).map((p) => p.fingerprint), [other.fp], 'the other still waits');
  } finally {
    gate.open();
    await w.waiting.close();
  }
});

test('a trusted list put in the folder while an admit runs is replaced, not merged', async () => {
  const stranger = await thumbprint((await developmentPasskey()).key);
  let folder = null;
  const w = await waitingWorld({ faults: async (at) => { if (at === 'checked') writeFileSync(join(folder, 'trusted-passkeys.json'), JSON.stringify({ passkeys: [stranger] })); } });
  folder = w.folder;
  try {
    const mine = await w.handed();
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.body.outcome, 'taken', JSON.stringify(r.body));
    assert.deepEqual(readTrusted(w.folder), [mine.T], 'exactly the one passkey the person named');
    assert.deepEqual((await status(w.port)).trusted, [mine.T]);
  } finally {
    await w.waiting.close();
  }
});

test('a start that fails after "yes" (the book cannot be written) answers not-started, leaves no slip and no trusted list, and the permission waits; the recorder still waits', async () => {
  const w = await waitingWorld();
  try {
    const mine = await w.handed();
    // A folder where the book's temporary file would be: the book cannot be written.
    mkdirSync(join(w.folder, 'book.jsonl.tmp'));
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.body.outcome, 'refused', JSON.stringify(r.body));
    assert.equal(r.body.code, 'not-started');
    for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(w.folder, name)), false, `${name} is put back`);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'the permission waits');
    assert.equal((await status(w.port)).waiting, true, 'still waiting');
    assert.equal((await runHook(w.port, 'PreToolUse', 'Read', { file_path: 'README.md' })).decision.permissionDecision, 'deny');
  } finally {
    await w.waiting.close();
  }
});

test('after a failed start, a file another program holds for a moment (removal refused twice with EBUSY) is still put back', async () => {
  let refusals = 0;
  const unlink = (path) => {
    if (path.endsWith('slip.json') && refusals < 2) {
      refusals++;
      throw Object.assign(new Error('resource busy or locked'), { code: 'EBUSY' });
    }
    return unlinkSync(path);
  };
  const w = await waitingWorld({ unlink });
  try {
    const mine = await w.handed();
    mkdirSync(join(w.folder, 'book.jsonl.tmp'));
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.body.code, 'not-started', JSON.stringify(r.body));
    assert.equal(refusals, 2);
    assert.doesNotMatch(r.body.message, /could not be removed/);
    for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(w.folder, name)), false, `${name} is put back`);
  } finally {
    await w.waiting.close();
  }
});

test('the options for tests cannot change the folder or the port the full recorder starts on', async () => {
  const elsewhere = tempFolder('provared-cc-elsewhere-');
  const w = await waitingWorld({ serviceOptions: { folder: elsewhere, on: null, port: 0 } });
  try {
    const mine = await w.handed();
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.body.outcome, 'taken', JSON.stringify(r.body));
    assert.equal((await status(w.port)).slip, mine.fp, 'the full recorder answers on the same port');
    assert.equal(existsSync(join(w.folder, 'book.jsonl')), true, 'in the same folder');
  } finally {
    await w.waiting.close();
  }
});

test('tool calls sent throughout the switch are each answered, refused or allowed, and none finds the port closed', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  let going = true;
  try {
    const mine = await w.handed();
    const answers = [];
    const ask = async () => {
      try {
        const r = await fetch(`http://127.0.0.1:${w.port}/before`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'provared.code.read' }), signal: AbortSignal.timeout(10000) });
        answers.push({ code: r.status, allowed: (await r.json()).allowed });
      } catch (e) {
        answers.push({ error: e.message });
      }
    };
    const callers = Array.from({ length: 4 }, async () => {
      while (going) await ask();
    });
    const taking = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the admit at its checks');
    gate.open();
    assert.equal((await within(taking, 30000, 'the admit')).body.outcome, 'taken');
    // A little longer, under the full recorder, measured on the monotonic clock.
    const after = answers.length;
    for (const until = performance.now() + 10000; answers.length < after + 8 && performance.now() < until;) await new Promise((r) => setTimeout(r, 20));
    going = false;
    await within(Promise.all(callers), 20000, 'the callers');
    assert.deepEqual(answers.filter((a) => a.error), [], 'every call was answered');
    assert.ok(answers.every((a) => a.code === 200), JSON.stringify(answers.filter((a) => a.code !== 200)));
    assert.ok(answers.some((a) => a.allowed === false), 'refused while waiting');
    assert.ok(answers.some((a) => a.allowed === true), 'allowed once taken');
    assert.equal(answers.at(-1).allowed, true);
  } finally {
    // The callers stop whatever happened above, so that a failure here never leaves them asking.
    going = false;
    gate.open();
    await w.waiting.close();
  }
});

test('records handed over while a permission is taken wait their turn and are then handled by the full recorder: a cancellation of it is taken, and another passkey\'s permission is answered by the full recorder\'s rules', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  try {
    const mine = await w.handed();
    const taking = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the admit at its checks');
    // Handed over now, each waits its turn in the waiting recorder, behind the admit.
    const prepared = await prepareCancellation({ slip: mine.fp, when: Date.now() });
    const cancellation = assembleCancellation(prepared, await w.passkey.sign(prepared.challenge));
    const stranger = await signSlip({ agentKeys: w.agent.keys, passkey: await developmentPasskey(), purpose: 'Handed over during the switch.' });
    const newReader = () => feedReader({ address: `http://127.0.0.1:${w.port}`, token: read(w.folder, 'feed-token').trim() });
    const cancelling = newReader().post('/hand-over', { kind: 'cancellation', cancellation });
    const handing = newReader().post('/hand-over', { kind: 'renewal', slip: stranger });
    await new Promise((r) => setTimeout(r, 300));
    gate.open();
    assert.equal((await within(taking, 30000, 'the admit')).body.outcome, 'taken');
    const cancelled = (await within(cancelling, 30000, 'the cancellation')).body;
    assert.equal(cancelled.outcome, 'taken', JSON.stringify(cancelled));
    assert.equal((await status(w.port)).cancelled, true, 'the permission just taken is cancelled');
    assert.equal((await runHook(w.port, 'PreToolUse', 'Read', { file_path: 'README.md' })).decision.permissionDecision, 'deny', 'no call is allowed under it');
    const said = (await within(handing, 30000, 'the hand-over')).body;
    // The full recorder's own answer for a passkey it does not trust (the uploader hands that over again).
    assert.equal(said.outcome, 'refused', JSON.stringify(said));
    assert.equal(said.code, 'passkey-not-trusted');
    // Kept by the full recorder, as it keeps any permission from a passkey it does not trust; the one taken no longer waits.
    assert.deepEqual(readWaitingPermissions(w.folder).map((p) => p.fingerprint), [said.fingerprint]);
    assert.notEqual(said.fingerprint, mine.fp);
  } finally {
    gate.open();
    await w.waiting.close();
  }
});

test('a folder that is no longer fresh at the admit (a file of held cancellations put there after the hand-over): "not-fresh", nothing written, and the permission waits', async () => {
  const w = await waitingWorld();
  try {
    const mine = await w.handed();
    writeFileSync(join(w.folder, 'held-cancellations.json'), JSON.stringify({ cancellations: [] }));
    const r = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    assert.equal(r.body.outcome, 'refused', JSON.stringify(r.body));
    assert.equal(r.body.code, 'not-fresh');
    assert.match(r.body.message, /held-cancellations\.json/);
    for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(w.folder, name)), false, `${name} is not written`);
    assert.equal(readWaitingPermissions(w.folder).length, 1, 'the permission waits');
    assert.equal((await status(w.port)).waiting, true);
  } finally {
    await w.waiting.close();
  }
});

test('an admit that reached the waiting recorder before the switch, and whose body arrived after it, is answered "not-waiting" and changes nothing', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  let release = () => {};
  try {
    const mine = await w.handed();
    const other = await w.handed(await developmentPasskey(), 'Another passkey\'s.');
    // Told when an admit reaches the waiting handler.
    const waitingOne = w.waiting.owner.handler;
    const handle = waitingOne.handle;
    let arrivals = 0;
    let second;
    const secondArrived = new Promise((r) => (second = r));
    waitingOne.handle = (req, res) => {
      if (req.url === '/admit' && ++arrivals === 2) second();
      return handle(req, res);
    };
    const first = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the first admit at its checks');
    // The second admit's first byte goes at once; the rest of its body only once the test lets it go.
    const letGo = new Promise((r) => (release = r));
    const slow = (url, init = {}) => {
      if (init.method !== 'POST') return fetch(url, init);
      const bytes = new TextEncoder().encode(init.body);
      const body = new ReadableStream({
        start(c) { c.enqueue(bytes.slice(0, 1)); },
        async pull(c) { await letGo; c.enqueue(bytes.slice(1)); c.close(); },
      });
      return fetch(url, { ...init, body, duplex: 'half' });
    };
    const later = feedReader({ address: `http://127.0.0.1:${w.port}`, token: read(w.folder, 'feed-token').trim(), fetchImpl: slow }).post('/admit', { fingerprint: other.fp, thumbprint: other.T, take: true });
    await within(secondArrived, 20000, 'the second admit at the waiting recorder');
    gate.open();
    assert.equal((await within(first, 30000, 'the first admit')).body.outcome, 'taken');
    release();
    const said = (await within(later, 30000, 'the second admit')).body;
    assert.equal(said.outcome, 'refused', JSON.stringify(said));
    assert.equal(said.code, 'not-waiting');
    assert.deepEqual(readTrusted(w.folder), [mine.T], 'the other passkey is not trusted');
    assert.equal((await status(w.port)).slip, mine.fp);
  } finally {
    release();
    gate.open();
    await w.waiting.close();
  }
});

test('in the waiting recorder, a declined permission no longer waits and is refused when handed over again; "take": false drops nothing', async () => {
  const w = await waitingWorld();
  try {
    const mine = await w.handed();
    const checked = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: false });
    assert.equal(checked.body.outcome, 'would-take', JSON.stringify(checked.body));
    assert.equal(readWaitingPermissions(w.folder).length, 1);
    for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(w.folder, name)), false, `${name} is not written by a check`);
    const sent = await w.reader.post('/admit', { slip: mine.slip, thumbprint: mine.T, take: true });
    assert.equal(sent.body.code, 'not-understood');
    const other = await thumbprint((await developmentPasskey()).key);
    assert.equal((await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: other, take: true })).body.code, 'other-passkey');
    const no = await w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, decline: true });
    assert.equal(no.body.outcome, 'declined', JSON.stringify(no.body));
    assert.equal(readWaitingPermissions(w.folder).length, 0);
    const again = (await w.reader.post('/hand-over', { kind: 'renewal', slip: mine.slip })).body;
    assert.equal(again.code, 'declined');
    assert.equal(readWaitingPermissions(w.folder).length, 0);
    assert.equal((await status(w.port)).waiting, true);
  } finally {
    await w.waiting.close();
  }
});

/** POST /stop with "body" as it is, and "headers" beside the usual ones: the code and the body of the answer. */
async function askToStop(port, body, headers = {}) {
  const r = await fetch(`http://127.0.0.1:${port}/stop`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body, signal: AbortSignal.timeout(10000) });
  return { code: r.status, body: await r.json() };
}

test('a stop asked only of a waiting recorder ({"waiting": true}): refused "busy" while an admit runs, which then completes; the full recorder then refuses it with "not-waiting" and keeps running; the port\'s checks still come first', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  try {
    const mine = await w.handed();
    const taking = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the admit at its checks');
    const busy = await askToStop(w.port, '{"waiting":true}');
    assert.equal(busy.code, 409, JSON.stringify(busy.body));
    assert.equal(busy.body.code, 'busy');
    assert.equal(busy.body.stopped, false);
    assert.equal((await status(w.port)).waiting, true, 'it still runs, and waits');
    gate.open();
    const took = await within(taking, 30000, 'the admit');
    assert.equal(took.body.outcome, 'taken', JSON.stringify(took.body));
    assert.equal((await status(w.port)).slip, mine.fp, 'the full recorder runs');
    // The full recorder has a permission in force: asked to stop only if it waits, it is not stopped.
    const refused = await askToStop(w.port, '{"waiting":true}');
    assert.equal(refused.code, 409, JSON.stringify(refused.body));
    assert.equal(refused.body.code, 'not-waiting');
    assert.equal(refused.body.stopped, false);
    // The port's checks of 0.1.1, before the body is read.
    assert.equal((await askToStop(w.port, '{"waiting":true}', { Origin: 'https://example.org' })).code, 403);
    assert.equal((await askToStop(w.port, '{"waiting":true}', { 'Content-Type': 'text/plain' })).code, 415);
    assert.equal((await status(w.port)).slip, mine.fp, 'the full recorder still runs');
    const pre = await runHook(w.port, 'PreToolUse', 'Read', { file_path: 'README.md' });
    assert.equal(pre.out, '', 'a call inside the permission is allowed');
  } finally {
    gate.open();
    await w.waiting.close();
  }
});

test('a stop asked only of a waiting recorder stops it where no admit runs; the port\'s checks still come first', async () => {
  const w = await waitingWorld();
  try {
    assert.equal((await askToStop(w.port, '{"waiting":true}', { 'Sec-Fetch-Site': 'cross-site' })).code, 403);
    assert.equal((await askToStop(w.port, '{"waiting":true}', { 'Content-Type': 'text/plain' })).code, 415);
    assert.equal((await status(w.port)).waiting, true, 'refused by the checks: it still runs');
    const stopped = await askToStop(w.port, '{"waiting":true}');
    assert.equal(stopped.code, 200, JSON.stringify(stopped.body));
    assert.equal(stopped.body.stopped, true);
    let gone = false;
    for (const until = performance.now() + 5000; !gone && performance.now() < until;) {
      gone = await status(w.port).then(() => false, () => true);
      if (!gone) await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal(gone, true, 'nothing answers within 5 seconds');
  } finally {
    await w.waiting.close();
  }
});

test('"use <file>" while an admit is being answered: the waiting recorder refuses its stop ("busy") and keeps running; once the admit is done, "use" goes on with the full recorder', async () => {
  const gate = gateAt('checked');
  const w = await waitingWorld({ faults: gate.faults });
  let stopAsked;
  const stopSeen = new Promise((r) => (stopAsked = r));
  w.waiting.owner.server.on('request', (req) => { if (req.url === '/stop') stopAsked(); });
  try {
    const mine = await w.handed();
    const taking = w.reader.post('/admit', { fingerprint: mine.fp, thumbprint: mine.T, take: true });
    await within(gate.reached, 20000, 'the admit at its checks');
    const file = join(tempFolder('provared-cc-use-'), 'slip.json');
    writeFileSync(file, JSON.stringify(mine.slip));
    const using = runCommand(['use', file], { folder: w.folder, port: w.port });
    await within(stopSeen, 30000, 'the stop that "use" asks');
    await new Promise((r) => setTimeout(r, 300));
    gate.open();
    const took = await within(taking, 30000, 'the admit');
    assert.equal(took.body.outcome, 'taken', JSON.stringify(took.body));
    const r = await within(using, 60000, '"use"');
    assert.equal(r.code, 0, `${r.out} ${r.err}`);
    assert.doesNotMatch(r.out, /was stopped/);
    assert.match(r.out, /The recorder is running/);
    const st = await status(w.port);
    assert.equal(st.slip, mine.fp, 'the full recorder runs, under the permission taken');
    assert.deepEqual(readTrusted(w.folder), [mine.T]);
  } finally {
    gate.open();
    await w.waiting.close();
  }
});
