// A new book at 90,000 entries, or on command (the founder's decision
// F-112), and calls allowed and not yet recorded counting against the
// limits. Every test uses a small number in place of 90,000, through the
// service's own option, in a temporary folder and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, fingerprint, fromBase64url, thumbprint } = await import('provared');
const { IN_FLIGHT_MS, KEPT_BOOK_HIGHEST, keptBooks, startService } = await import('../recorder.mjs');
const { ACTIONS, freePort, runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const lines = (text) => text.split('\n').filter(Boolean);
const slipFingerprint = (slip) => fingerprint(fromBase64url(slip.payload));
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** Every book in the folder, oldest first, the one in force last. */
const allBooks = (folder) => [...keptBooks(folder).map((k) => k.file), ...(existsSync(join(folder, 'book.jsonl')) ? ['book.jsonl'] : [])];

/** Each book checked on its own, with the passkeys and the recorder named. */
async function checkEach(folder, passkeys, sealer) {
  const out = [];
  for (const file of allBooks(folder)) {
    const result = await checkBook(read(folder, file), { issuerKeys: passkeys, sealKeys: [sealer] });
    assert.equal(result.summary.intact, true, `${file}: ${JSON.stringify(result.entries.flatMap((e) => e.problems))}`);
    assert.equal(result.summary.withinSlips, true, `${file}: ${JSON.stringify(result.entries.flatMap((e) => e.breaches ?? []))}`);
    assert.equal(result.entries[0].kind, 'slip', `${file} begins with a permission`);
    out.push({ file, result, stubs: result.entries.filter((e) => e.kind === 'stub') });
  }
  return out;
}
// The fingerprint of each call's arguments, from every stub in every book: each call once.
const callsIn = (checked) => checked.flatMap((b) => b.stubs.map((s) => s.content.details[0].sha256));
const lastKind = (folder, file) => Object.keys(JSON.parse(lines(read(folder, file)).at(-1)))[0];

// --- calls allowed and not yet recorded ---

test('within a period: the stubs in the period, the calls allowed and not yet recorded, and this one must fit', async () => {
  const { folder, passkey } = await world([{ action: 'provared.code.run', count: 3, per: 3600 }]);
  const service = await startService({ folder, port: 0 });
  try {
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' })).code, 0);
    const asked = await Promise.all([1, 2, 3, 4].map((i) => runHook(service.port, 'PreToolUse', 'Bash', { command: `npm run p${i}` }, { more: { tool_use_id: `p${i}` } })));
    const allowed = asked.flatMap((r, i) => (r.out === '' ? [i + 1] : []));
    assert.equal(allowed.length, 2, 'one recorded and two allowed fill the three in any hour');
    assert.match(asked.find((r) => r.out !== '').decision.permissionDecisionReason, /\(3 in any hour\)/);
    assert.equal((await status(service.port)).callsNotYetRecorded, 2);
    // Another action is not held up by them.
    assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'a' }, { more: { tool_use_id: 'r1' } })).out, '');
    for (const i of allowed) assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: `npm run p${i}` }, { more: { tool_use_id: `p${i}` } })).code, 0);
    const result = await checkBook(read(folder, 'book.jsonl'), { issuerKeys: [await thumbprint(passkey.key)] });
    assert.equal(result.summary.withinSlips, true);
  } finally {
    await service.close();
  }
});

test('a call whose stub never comes stops counting after the time set, and one recorded stops at once', async () => {
  const { folder } = await world([{ action: 'provared.code.run', count: 2 }]);
  // The clock the waiting calls are measured by is moved by the test, so the test does not rest on the computer's speed.
  let ahead = 0;
  const service = await startService({ folder, port: 0, clock: () => Date.now() + ahead });
  try {
    const ask = (id) => runHook(service.port, 'PreToolUse', 'Bash', { command: `npm run ${id}` }, { more: { tool_use_id: id } });
    assert.equal((await ask('a')).out, '', 'a allowed');
    assert.equal((await ask('b')).out, '', 'b allowed: with a, two');
    assert.notEqual((await ask('c')).out, '', 'c refused while a and b are not yet recorded');
    // b is recorded: it is now a stub, counted by the check before acting; a still waits.
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm run b' }, { more: { tool_use_id: 'b' } })).code, 0);
    assert.notEqual((await ask('c')).out, '', 'c refused: b recorded and a not yet');
    // a never comes back (refused at the person's prompt, say): after the time set it no longer counts.
    ahead = IN_FLIGHT_MS - 60000;
    assert.notEqual((await ask('c')).out, '', 'c still refused a minute before the 15 minutes are up');
    ahead = IN_FLIGHT_MS + 1000;
    assert.equal((await ask('c')).out, '', 'c allowed once a has stopped counting');
    assert.equal((await status(service.port)).callsNotYetRecorded, 1);
  } finally {
    await service.close();
  }
});

test('calls allowed under the permission before a renewal do not count against the new one', async () => {
  const { folder, passkey, agent } = await world([{ action: 'provared.code.run', count: 1 }]);
  const service = await startService({ folder, port: 0 });
  try {
    assert.equal((await runHook(service.port, 'PreToolUse', 'Bash', { command: 'x' }, { more: { tool_use_id: 'x' } })).out, '');
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, limits: [{ action: 'provared.code.run', count: 1 }], purpose: 'renewed' }));
    assert.equal((await runHook(service.port, 'PreToolUse', 'Bash', { command: 'y' }, { more: { tool_use_id: 'y' } })).out, '', 'the new permission has its own count');
  } finally {
    await service.close();
  }
});

test('a call that stops counting is still recorded under the permission it was allowed under, however long it ran, where no new book has begun', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  const service = await startService({ folder, port: 0, inFlightMs: 300 });
  try {
    assert.equal((await runHook(service.port, 'PreToolUse', 'Bash', { command: 'long' }, { more: { tool_use_id: 'long' } })).out, '');
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, purpose: 'renewed' }));
    await pause(500);
    assert.equal((await status(service.port)).callsNotYetRecorded, 0, 'it no longer counts');
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'long' }, { more: { tool_use_id: 'long' } })).code, 0);
    const result = await checkBook(read(folder, 'book.jsonl'), { issuerKeys: [await thumbprint(passkey.key)] });
    assert.equal(result.summary.intact, true);
    assert.equal(result.entries.find((e) => e.kind === 'stub').slip, await slipFingerprint(first));
  } finally {
    await service.close();
  }
});

// A stub dated after now (up to 300 seconds ahead of the clock) is counted
// with the waiting calls, but no test can tell: while the last stub of the
// chain is dated ahead, the check before acting refuses every call
// ("time-went-backwards"), as this shows.
test('while the last stub is dated ahead of the clock, no call is allowed', async () => {
  const { folder } = await world([{ action: 'provared.code.run', count: 2, per: 3600 }]);
  const service = await startService({ folder, port: 0 });
  try {
    const post = (path, body) => fetch(`http://127.0.0.1:${service.port}${path}`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
    const run = (id) => ({ action: 'provared.code.run', details: [{ name: 'Bash', sha256: `${id}${'A'.repeat(43 - id.length)}` }], toolUseId: id });
    assert.ok(!(await post('/record', { ...run('ahead'), when: Date.now() + 200000 })).error);
    const a = await post('/before', run('a'));
    assert.equal(a.allowed, false);
    assert.equal(a.problems[0].code, 'time-went-backwards');
  } finally {
    await service.close();
  }
});

// --- a new book ---

test('a new book at the limit, under many calls at once: every call is recorded once, in the book it was allowed under, and each book checks on its own', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0, newBookAt: { entries: 8 } });
  try {
    const sealer = (await status(service.port)).sealer;
    const N = 30;
    // Each call asks first and is recorded after, as Claude Code's hooks do; ten calls run side by side, three times over.
    const done = [];
    for (let wave = 0; wave < 3; wave++) {
      done.push(...await Promise.all(Array.from({ length: 10 }, async (_, j) => {
        const i = wave * 10 + j;
        const pre = await runHook(service.port, 'PreToolUse', 'Read', { file_path: `f${i}` }, { more: { tool_use_id: `call${i}` } });
        const post = await runHook(service.port, 'PostToolUse', 'Read', { file_path: `f${i}` }, { more: { tool_use_id: `call${i}` } });
        return { pre, post };
      })));
    }
    for (const { pre, post } of done) {
      assert.equal(pre.out, '', `refused: ${pre.out}`);
      assert.equal(post.code, 0, post.err);
    }
    const kept = keptBooks(folder);
    assert.ok(kept.length >= 2, `${kept.length} books kept`);
    assert.deepEqual(kept.map((k) => k.number), kept.map((_, i) => i + 1), 'numbered from 1 in order');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    const calls = callsIn(checked);
    assert.equal(calls.length, N, 'every call has one stub');
    assert.equal(new Set(calls).size, N, 'no call has two');
    for (const k of kept) assert.equal(lastKind(folder, k.file), 'seal', `${k.file} ends with a seal`);
    for (const k of kept) assert.ok(lines(read(folder, k.file)).length <= 8 + 1 + N, 'a kept book stops near the limit');
    assert.deepEqual((await status(service.port)).keptBooks, kept.map((k) => k.file));
  } finally {
    await service.close();
  }
});

test('a call allowed under a book and taken after the new book began is recorded in the book it was allowed under, which is sealed again after it', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const sealer = (await status(service.port)).sealer;
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'one' });
    assert.equal((await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { more: { tool_use_id: 'late' } })).out, '');
    const made = await service.newBook();
    assert.equal(made.kept, 'book-1.jsonl');
    assert.equal(lastKind(folder, 'book-1.jsonl'), 'seal');
    assert.equal(lines(read(folder, 'book.jsonl')).length, 1, 'the new book holds the permission in force alone');
    // A call asked after the switch goes into the new book.
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'two' });
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' }, { more: { tool_use_id: 'late' } })).code, 0);
    const kept = lines(read(folder, 'book-1.jsonl'));
    assert.equal(Object.keys(JSON.parse(kept.at(-2)))[0], 'stub', 'the late call is in the kept book, after its first seal');
    assert.equal(Object.keys(JSON.parse(kept.at(-3)))[0], 'seal');
    assert.equal(lastKind(folder, 'book-1.jsonl'), 'seal', 'and the kept book is sealed again after it');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.deepEqual(checked.map((b) => b.stubs.length), [2, 1]);
    // The new book begins with the same permission, and its chain starts at 0.
    assert.equal(checked[1].stubs[0].content.seq, 0);
    assert.equal(checked[1].result.entries[0].fingerprint, checked[0].result.entries[0].fingerprint);
  } finally {
    await service.close();
  }
});

test('a call allowed under a kept book that never comes back holds it open only for the time set; a stub after that goes into the book in force', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0, inFlightMs: 300 });
  try {
    const sealer = (await status(service.port)).sealer;
    assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'x' }, { more: { tool_use_id: 'gone' } })).out, '');
    await service.newBook();
    const keptBefore = read(folder, 'book-1.jsonl');
    await pause(500);
    await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'y' }, { more: { tool_use_id: 'other' } });
    assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' }, { more: { tool_use_id: 'gone' } })).code, 0);
    assert.equal(read(folder, 'book-1.jsonl'), keptBefore, 'the kept book is not changed');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.deepEqual(checked.map((b) => b.stubs.length), [0, 1]);
  } finally {
    await service.close();
  }
});

test('a new book begins exactly when the book reaches the number of entries, and a book that ends with a seal is not sealed again', async () => {
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0, newBookAt: { entries: 5 } });
  try {
    for (let i = 0; i < 3; i++) await runHook(service.port, 'PostToolUse', 'Read', { file_path: `e${i}` });
    assert.deepEqual(keptBooks(folder), [], 'four entries: no new book yet');
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'e3' });
    assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl'], 'at five entries, a new book');
    const kept = lines(read(folder, 'book-1.jsonl'));
    assert.equal(kept.length, 6, 'the five entries and the seal');
    assert.equal(lastKind(folder, 'book-1.jsonl'), 'seal');
    // A book that ends with a seal: a new book adds no second seal.
    await service.seal();
    const before = read(folder, 'book.jsonl');
    await service.newBook();
    assert.equal(read(folder, 'book-2.jsonl'), before, 'kept as it was, with its one seal');
  } finally {
    await service.close();
  }
});

test('a new book begins after a seal or a renewal that fills the book, through the service and through its calls', async () => {
  for (const how of ['seal', 'renew', 'POST /seal', 'POST /renew']) {
    const { folder, passkey, agent } = await world([]);
    const service = await startService({ folder, port: 0, newBookAt: { entries: 3 } });
    try {
      await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' });
      assert.deepEqual(keptBooks(folder), [], `${how}: two entries`);
      const post = (path, body) => fetch(`http://127.0.0.1:${service.port}${path}`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
      const slip = how.endsWith('renew') ? await signSlip({ agentKeys: agent.keys, passkey, purpose: 'renewed' }) : null;
      if (how === 'seal') await service.seal();
      if (how === 'renew') await service.renew(slip);
      if (how === 'POST /seal') await post('/seal', {});
      if (how === 'POST /renew') await post('/renew', { slip });
      assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl'], `${how}: the third entry begins a new book`);
    } finally {
      await service.close();
    }
  }
});

test('a kept book is numbered after the highest number there, never in a gap, and no kept book is replaced', async () => {
  const { folder } = await world([]);
  writeFileSync(join(folder, 'book-1.jsonl'), 'the first kept book\n');
  writeFileSync(join(folder, 'book-3.jsonl'), 'the third kept book\n');
  const service = await startService({ folder, port: 0 });
  try {
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' });
    const made = await service.newBook();
    assert.equal(made.kept, 'book-4.jsonl');
    assert.equal(read(folder, 'book-1.jsonl'), 'the first kept book\n');
    assert.equal(read(folder, 'book-3.jsonl'), 'the third kept book\n');
    assert.ok(!existsSync(join(folder, 'book-2.jsonl')));
  } finally {
    await service.close();
  }
});

test('a late stub written into a kept book is on the disk before its answer, while another call may still come back', async () => {
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    for (const id of ['one', 'two']) assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: id }, { more: { tool_use_id: id } })).out, '');
    await service.newBook();
    const sealedAt = lines(read(folder, 'book-1.jsonl')).length;
    assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'one' }, { more: { tool_use_id: 'one' } })).code, 0);
    // "two" may still come back, so the kept book is not sealed again yet; the stub of "one" is on the disk all the same.
    const now = lines(read(folder, 'book-1.jsonl'));
    assert.equal(now.length, sealedAt + 1, 'the late stub is in the kept book on the disk');
    assert.equal(Object.keys(JSON.parse(now.at(-1)))[0], 'stub');
  } finally {
    await service.close();
  }
});

test('a new book that could not be started is tried again a minute later', async () => {
  const { folder, passkey } = await world([]);
  let ahead = 0;
  let tries = 0;
  const service = await startService({ folder, port: 0, newBookAt: { entries: 3 }, clock: () => Date.now() + ahead, faults: (at) => { if (at === 'sealed' && tries++ === 0) throw new Error('the file is held open'); } });
  try {
    const sealer = (await status(service.port)).sealer;
    for (let i = 0; i < 3; i++) await runHook(service.port, 'PostToolUse', 'Read', { file_path: `r${i}` });
    assert.deepEqual(keptBooks(folder), [], 'the first try failed');
    assert.equal(tries, 1, 'and is not tried again within the minute');
    ahead = 61000;
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'later' });
    assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl'], 'tried again a minute later, and made');
    assert.equal((await status(service.port)).newBookProblem, undefined);
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.equal(callsIn(checked).length, 4);
  } finally {
    await service.close();
  }
});

test('a kept book that a stop left ending with a late stub is sealed at the next start', async () => {
  const { folder, passkey } = await world([]);
  let service = await startService({ folder, port: 0 });
  const sealer = (await status(service.port)).sealer;
  for (const id of ['one', 'two']) await runHook(service.port, 'PreToolUse', 'Read', { file_path: id }, { more: { tool_use_id: id } });
  await service.newBook();
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'one' }, { more: { tool_use_id: 'one' } });
  // The recorder stops while "two" may still come back: the kept book ends with the late stub.
  await service.close();
  assert.equal(lastKind(folder, 'book-1.jsonl'), 'stub');
  service = await startService({ folder, port: 0 });
  try {
    assert.equal(lastKind(folder, 'book-1.jsonl'), 'seal', 'sealed at the start');
    await checkEach(folder, [await thumbprint(passkey.key)], sealer);
  } finally {
    await service.close();
  }
});

test('a stop between the rename and the new book, after the permission has ended, does not keep the recorder from starting', async () => {
  const { folder, passkey, agent } = await world([]);
  // A permission that ends two seconds from now.
  const short = await signSlip({ agentKeys: agent.keys, passkey, until: Date.now() + 2000 });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(short));
  let service = await startService({ folder, port: 0, faults: (at) => { if (at === 'kept') throw new Error('stopped'); } });
  const sealer = (await status(service.port)).sealer;
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' });
  await assert.rejects(service.newBook());
  await service.close();
  assert.ok(!existsSync(join(folder, 'book.jsonl')));
  await pause(Math.max(0, Date.parse(JSON.parse(new TextDecoder().decode(fromBase64url(short.payload))).validUntil) + 1000 - Date.now()));
  service = await startService({ folder, port: 0 });
  try {
    assert.equal(lines(read(folder, 'book.jsonl')).length, 1, 'the new book begins with the permission, which has ended');
    const sealed = await service.seal();
    assert.equal(typeof sealed.fingerprint, 'string', 'seal works');
    assert.equal((await status(service.port)).entries, 2, 'status works');
    const asked = await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'y' }, { more: { tool_use_id: 'y' } });
    assert.equal(asked.decision?.permissionDecision, 'deny', 'every call is refused');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.deepEqual(checked.map((b) => b.stubs.length), [1, 0]);
  } finally {
    await service.close();
  }
});

test('a new book at a size in bytes, before the number of entries is reached', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0, newBookAt: { bytes: 40000 } });
  try {
    const sealer = (await status(service.port)).sealer;
    for (let i = 0; i < 6; i++) assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: `s${i}` })).code, 0);
    assert.ok(keptBooks(folder).length >= 1, 'a book was kept');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.equal(callsIn(checked).length, 6);
  } finally {
    await service.close();
  }
});

test('a book already full when the service starts is kept, and a new one begun, before any call', async () => {
  const { folder, passkey } = await world([]);
  let service = await startService({ folder, port: 0 });
  for (let i = 0; i < 4; i++) await runHook(service.port, 'PostToolUse', 'Read', { file_path: `s${i}` });
  const sealer = (await status(service.port)).sealer;
  await service.close();
  service = await startService({ folder, port: 0, newBookAt: { entries: 3 } });
  try {
    assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl']);
    assert.equal((await status(service.port)).entries, 1);
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'after' });
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.deepEqual(checked.map((b) => b.stubs.length), [4, 1]);
  } finally {
    await service.close();
  }
});

test('a new book and a renewal at the same moment: no line is lost or doubled, and the new book begins with the permission in force', async () => {
  for (const order of ['renew first', 'new book first']) {
    const { folder, passkey, agent } = await world([]);
    const service = await startService({ folder, port: 0 });
    try {
      const sealer = (await status(service.port)).sealer;
      const post = (path, body) => fetch(`http://127.0.0.1:${service.port}${path}`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
      const second = await signSlip({ agentKeys: agent.keys, passkey, purpose: 'renewed' });
      const calls = Array.from({ length: 10 }, (_, i) => ({ action: 'provared.code.read', details: [{ name: 'Read', sha256: `${String(i).padStart(2, '0')}${'A'.repeat(41)}` }], toolUseId: `m${i}` }));
      const asked = await Promise.all(calls.slice(0, 5).map((c) => post('/before', c)));
      assert.ok(asked.every((a) => a.allowed));
      const both = order === 'renew first' ? [post('/renew', { slip: second }), post('/new-book', {})] : [post('/new-book', {}), post('/renew', { slip: second })];
      const answers = await Promise.all([...both, ...calls.map((c) => post('/record', c))]);
      for (const a of answers) assert.ok(!a.error, JSON.stringify(a));
      const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
      const recorded = callsIn(checked);
      assert.equal(recorded.length, 10, `${order}: every call once`);
      assert.equal(new Set(recorded).size, 10, `${order}: no call twice`);
      const s = await status(service.port);
      assert.equal(s.slip, await slipFingerprint(second));
      assert.equal(read(folder, 'slip.json'), JSON.stringify(second));
      // Whatever the order, the book in force holds the permission in force.
      const inForce = checked.at(-1).result.entries.filter((e) => e.kind === 'slip').map((e) => e.fingerprint);
      assert.ok(inForce.includes(s.slip), `${order}: the new book holds the permission in force`);
      assert.equal(keptBooks(folder).length, 1);
    } finally {
      await service.close();
    }
  }
});

for (const step of ['sealed', 'kept', 'written']) {
  test(`a stop at each step of a new book (after "${step}") leaves the folder as it was or the switch completed, never half`, async () => {
    const { folder, passkey } = await world([]);
    const crash = new Error(`stopped after ${step}`);
    let service = await startService({ folder, port: 0, faults: (at) => { if (at === step) throw crash; } });
    const sealer = (await status(service.port)).sealer;
    for (let i = 0; i < 3; i++) await runHook(service.port, 'PostToolUse', 'Read', { file_path: `c${i}` });
    const before = read(folder, 'book.jsonl');
    await assert.rejects(service.newBook(), (e) => e === crash);
    await service.close();
    // What the stop left.
    const names = readdirSync(folder);
    assert.ok(!names.some((n) => n.endsWith('.tmp')), `no temporary file is left: ${names}`);
    if (step === 'sealed') {
      assert.ok(!existsSync(join(folder, 'book-1.jsonl')), 'nothing kept');
      assert.ok(read(folder, 'book.jsonl').startsWith(before), 'the book as it was');
      assert.equal(lines(read(folder, 'book.jsonl')).length, lines(before).length + 1, 'with its seal');
    } else {
      assert.ok(read(folder, 'book-1.jsonl').startsWith(before), 'the book is kept whole');
      assert.equal(existsSync(join(folder, 'book.jsonl')), step === 'written');
    }
    // The next start: the switch completed where it had begun, and calls go on.
    service = await startService({ folder, port: 0 });
    try {
      await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'after' });
      const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
      assert.deepEqual(checked.map((b) => b.stubs.length), step === 'sealed' ? [4] : [3, 1]);
      assert.equal(new Set(callsIn(checked)).size, 4);
      if (step !== 'sealed') assert.equal(lastKind(folder, 'book-1.jsonl'), 'seal');
    } finally {
      await service.close();
    }
  });
}

test('a new book that cannot be started at the limit leaves the book in force going on, and status says why', async () => {
  const { folder, passkey } = await world([]);
  let tries = 0;
  const service = await startService({ folder, port: 0, newBookAt: { entries: 3 }, faults: (at) => { if (at === 'sealed' && tries++ === 0) throw new Error('the file is held open'); } });
  try {
    const sealer = (await status(service.port)).sealer;
    for (let i = 0; i < 4; i++) assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: `w${i}` })).code, 0);
    const s = await status(service.port);
    assert.match(s.newBookProblem, /A new book could not be started: the file is held open/);
    assert.deepEqual(keptBooks(folder), [], 'nothing kept');
    // Asked for by hand, it is made, and the problem is gone.
    await service.newBook();
    assert.equal((await status(service.port)).newBookProblem, undefined);
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.deepEqual(checked.map((b) => b.stubs.length), [4, 0]);
  } finally {
    await service.close();
  }
});

test('the command new-book, with the recorder running and not, and check of a kept book', async () => {
  const { folder, passkey } = await world([]);
  const port = await freePort();
  const service = await startService({ folder, port });
  try {
    await runHook(port, 'PostToolUse', 'Read', { file_path: 'a' });
    const made = await runCommand(['new-book'], { folder, port });
    assert.equal(made.code, 0, made.err);
    assert.match(made.out, /kept as .*book-1\.jsonl \(3 entries\)/);
    const shown = JSON.parse((await runCommand(['status'], { folder, port })).out);
    assert.deepEqual(shown.keptBooks, ['book-1.jsonl']);
    assert.deepEqual(shown.newBookAt, { entries: 90000, bytes: 100000000 });
  } finally {
    await service.close();
  }
  // Not running: the book is opened here.
  const second = await runCommand(['new-book'], { folder, port });
  assert.equal(second.code, 0, second.err);
  assert.match(second.out, /book-2\.jsonl/);
  const passkeyThumbprint = await thumbprint(passkey.key);
  const checked = await runCommand(['check', 'book-1.jsonl', '--issuer', passkeyThumbprint], { folder, port });
  assert.equal(checked.code, 0, checked.out + checked.err);
  const missing = await runCommand(['check', 'book-9.jsonl', '--issuer', passkeyThumbprint], { folder, port });
  assert.equal(missing.code, 2);
  assert.match(missing.err, /There is no book at/);
});

test('a kept book is found only by its exact name', () => {
  const folder = tempFolder();
  for (const name of ['book-1.jsonl', 'book-10.jsonl', 'book-2.jsonl', 'book-0.jsonl', 'book-02.jsonl', 'book-3.jsonl.tmp', 'book.jsonl', 'notebook-4.jsonl']) writeFileSync(join(folder, name), '');
  assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl', 'book-2.jsonl', 'book-10.jsonl']);
});

// --- every limit enforced across the books ---

const RELEASE = 'provared.code.release';
const asker = (port) => {
  const post = (path, body) => fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
  let n = 0;
  const call = (action = RELEASE, more = {}) => ({ action, details: [{ name: 'Bash', sha256: `${String(++n).padStart(3, '0')}${'A'.repeat(40)}` }], toolUseId: `c${n}`, ...more });
  // Ask, and where allowed, record: what the hook does before and after a call.
  const take = async (action, more) => {
    const c = call(action, more);
    const said = await post('/before', c);
    if (said.allowed) assert.ok(!(await post('/record', c)).error);
    return said;
  };
  return { post, call, take };
};

test('a new book by command restarts no limit: one release a day stays one, across books', async () => {
  const { folder, passkey } = await world([{ action: RELEASE, count: 1, per: 86400 }]);
  const service = await startService({ folder, port: 0 });
  try {
    const sealer = (await status(service.port)).sealer;
    const { post, take } = asker(service.port);
    assert.equal((await take()).allowed, true, 'the first release');
    for (let i = 0; i < 3; i++) {
      assert.ok((await post('/new-book', {})).kept, 'a new book');
      const said = await take();
      assert.equal(said.allowed, false, `a release in new book ${i + 2}`);
      assert.equal(said.breaches[0].code, 'over-period-limit');
      assert.match(said.breaches[0].message, /books kept before this one \(1\).*A new book starts no limit again/);
    }
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.equal(checked.flatMap((b) => b.stubs).length, 1, 'one release in all the books');
  } finally {
    await service.close();
  }
});

test('an automatic new book restarts no limit, and a call allowed before it still counts after it', async () => {
  const { folder } = await world([{ action: RELEASE, count: 2, per: 86400 }]);
  const service = await startService({ folder, port: 0, newBookAt: { entries: 3 } });
  try {
    const { post, call, take } = asker(service.port);
    assert.equal((await take()).allowed, true, 'release 1');
    // Allowed, and still running when the book fills.
    const waiting = call();
    assert.equal((await post('/before', waiting)).allowed, true, 'release 2 allowed, not yet recorded');
    await take('provared.code.read');
    assert.deepEqual(keptBooks(folder).map((k) => k.file), ['book-1.jsonl'], 'the third entry began a new book');
    assert.equal((await take()).allowed, false, 'release 3: one kept, one waiting');
    assert.ok(!(await post('/record', waiting)).error);
    assert.equal((await take()).allowed, false, 'release 3: two kept');
  } finally {
    await service.close();
  }
});

test('a restart after a new book restarts no limit: the kept books are counted again when the recorder starts', async () => {
  const { folder } = await world([{ action: RELEASE, count: 1, per: 86400 }]);
  let service = await startService({ folder, port: 0 });
  assert.equal((await asker(service.port).take()).allowed, true);
  await service.newBook();
  await service.close();
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await asker(service.port).take()).allowed, false, 'refused after the restart');
  } finally {
    await service.close();
  }
});

test('a renewal starts the new permission\'s own counts, as before, across books too', async () => {
  const { folder, passkey, agent } = await world([{ action: RELEASE, count: 1, per: 86400 }]);
  const service = await startService({ folder, port: 0 });
  try {
    const { take } = asker(service.port);
    assert.equal((await take()).allowed, true);
    await service.newBook();
    assert.equal((await take()).allowed, false, 'the same permission in a new book: refused');
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, limits: [{ action: RELEASE, count: 1, per: 86400 }], purpose: 'renewed' }));
    assert.equal((await take()).allowed, true, 'the new permission has its own count');
    await service.newBook();
    assert.equal((await take()).allowed, false, 'and keeps it across a new book');
  } finally {
    await service.close();
  }
});

test('a limit with no period, a count or a total, holds across three books', async () => {
  const { folder, passkey, agent } = await world([]);
  const limits = [{ action: RELEASE, count: 2 }, { action: 'send-order', max: 100, unit: 'GBP' }];
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ agentKeys: agent.keys, passkey, limits, actions: [...ACTIONS, 'send-order'] })));
  const service = await startService({ folder, port: 0 });
  try {
    const sealer = (await status(service.port)).sealer;
    const { take } = asker(service.port);
    const send = (value) => take('send-order', { amount: { unit: 'GBP', value } });
    assert.equal((await take()).allowed, true, 'release 1, book 1');
    assert.equal((await send(60)).allowed, true, '60 GBP, book 1');
    await service.newBook();
    assert.equal((await take()).allowed, true, 'release 2, book 2');
    await service.newBook();
    const third = await take();
    assert.equal(third.allowed, false, 'release 3, book 3');
    assert.equal(third.breaches[0].code, 'over-count-limit');
    const over = await send(50);
    assert.equal(over.allowed, false, '60 and 50 GBP');
    assert.equal(over.breaches[0].code, 'over-limit');
    assert.match(over.breaches[0].message, /\(60 GBP\).*110 GBP.*allows 100 GBP in all/);
    assert.equal((await send(40)).allowed, true, '60 and 40 GBP');
    const checked = await checkEach(folder, [await thumbprint(passkey.key)], sealer);
    assert.equal(checked.length, 3);
  } finally {
    await service.close();
  }
});

test('a receipt in a kept book counts only within the period of a limit', async () => {
  const { folder } = await world([{ action: RELEASE, count: 1, per: 3600 }]);
  let ahead = 0;
  const service = await startService({ folder, port: 0, clock: () => Date.now() + ahead });
  try {
    const { take } = asker(service.port);
    assert.equal((await take()).allowed, true);
    await service.newBook();
    ahead = 1800 * 1000;
    assert.equal((await take()).allowed, false, 'half an hour later: still within the hour');
    ahead = 3601 * 1000;
    assert.equal((await take()).allowed, true, 'an hour later: the kept receipt is out of the period');
  } finally {
    await service.close();
  }
});

test('a receipt in a kept book dated after the recorder\'s clock still counts, as where the computer\'s clock steps back after a new book', async () => {
  const { folder, passkey, agent } = await world([]);
  // In force from two hours ago, so that a clock set back ten minutes is still within it.
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(await signSlip({ agentKeys: agent.keys, passkey, limits: [{ action: RELEASE, count: 1, per: 3600 }], from: Date.now() - 7200000 })));
  let ahead = 0;
  const service = await startService({ folder, port: 0, clock: () => Date.now() + ahead });
  try {
    const { take } = asker(service.port);
    assert.equal((await take()).allowed, true, 'the first release');
    await service.newBook();
    // The new book's own chain holds no stub, so nothing in it is dated ahead of the clock.
    ahead = -600 * 1000;
    const said = await take();
    assert.equal(said.allowed, false, 'the kept release, now dated ten minutes after the clock, still counts');
    assert.equal(said.breaches[0].code, 'over-period-limit');
    assert.match(said.breaches[0].message, /books kept before this one \(1\)/);
    assert.equal((await take('provared.code.read')).allowed, true, 'another action is allowed: the refusal is the limit\'s alone');
  } finally {
    await service.close();
  }
});

test('a permission put in place while the recorder is stopped, which has ended, is refused at the start', async () => {
  const { folder, passkey, agent, slip } = await world([]);
  const ended = await signSlip({ agentKeys: agent.keys, passkey, from: Date.now() - 7200000, until: Date.now() - 3600000 });
  // Refused at the start; a recorder that starts all the same is stopped, so that the test ends.
  const refusesToStart = async (where) => {
    let started;
    try {
      started = await startService({ folder: where, port: 0 });
    } catch (e) {
      assert.match(e.message, /ended at/);
      return;
    }
    await started.close();
    assert.fail('the recorder started with a permission that has ended');
  };
  // In a folder with no book yet.
  const fresh = tempFolder();
  writeFileSync(join(fresh, 'agent-keys.jwk'), read(folder, 'agent-keys.jwk'));
  writeFileSync(join(fresh, 'slip.json'), JSON.stringify(ended));
  await refusesToStart(fresh);
  assert.ok(!existsSync(join(fresh, 'book.jsonl')), 'no book is begun');
  // In a folder whose book holds an earlier permission.
  let service = await startService({ folder, port: 0 });
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'x' });
  await service.close();
  const before = read(folder, 'book.jsonl');
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(ended));
  await refusesToStart(folder);
  assert.equal(read(folder, 'book.jsonl'), before, 'the book is as it was');
  // With the permission in force put back, the recorder starts again.
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(slip));
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await status(service.port)).entries, lines(before).length);
  } finally {
    await service.close();
  }
});

test('a kept book is read by one rule, and the recorder keeps no book under a name that rule would not read', async () => {
  // The rule reads the highest number a kept book may have, and nothing past it.
  const names = tempFolder();
  for (const name of [`book-${KEPT_BOOK_HIGHEST}.jsonl`, `book-${KEPT_BOOK_HIGHEST + 1}.jsonl`]) writeFileSync(join(names, name), '');
  assert.deepEqual(keptBooks(names).map((k) => k.file), [`book-${KEPT_BOOK_HIGHEST}.jsonl`]);
  // A valid book holding only the permission, put in the folder by hand at that number (the reviewer's stray case).
  const { folder } = await world([{ action: RELEASE, count: 1, per: 86400 }]);
  let service = await startService({ folder, port: 0 });
  await service.close();
  writeFileSync(join(folder, `book-${KEPT_BOOK_HIGHEST}.jsonl`), read(folder, 'book.jsonl'));
  service = await startService({ folder, port: 0, newBookAt: { entries: 3 } });
  try {
    const { post, take } = asker(service.port);
    assert.equal((await take()).allowed, true, 'the first release');
    const before = read(folder, 'book.jsonl');
    const made = await post('/new-book', {});
    assert.equal(made.kept, undefined, 'no new book');
    assert.match(JSON.stringify(made), /highest number a kept book may have/);
    assert.equal(read(folder, 'book.jsonl'), before, 'the book in force is as it was, with no seal added');
    // At the size set, the book is not switched either; recording goes on, and status says why.
    assert.equal((await take('provared.code.read')).allowed, true);
    assert.match((await status(service.port)).newBookProblem, /highest number a kept book may have/);
    assert.equal((await take()).allowed, false, 'a second release in the day');
  } finally {
    await service.close();
  }
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await asker(service.port).take()).allowed, false, 'a second release in the day, after a restart');
    assert.deepEqual(keptBooks(folder).map((k) => k.file), [`book-${KEPT_BOOK_HIGHEST}.jsonl`]);
    assert.deepEqual(readdirSync(folder).filter((f) => /^book-\d+\.jsonl$/.test(f)), [`book-${KEPT_BOOK_HIGHEST}.jsonl`], 'no book is kept under a name the rule does not read');
  } finally {
    await service.close();
  }
});
