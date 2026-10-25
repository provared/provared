// The faults found by the first independent review of the recorder beside
// Claude Code (13 October 2026), each kept as a test that fails on the code
// before its fix.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, entryLine, fingerprint, fromBase64url, sha256, thumbprint, toBase64url, utf8 } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { bookSaver, checkNewSlip, hookSettings, replaceFile, startService, writeHooks } = await import('../recorder.mjs');
const { freePort, runCommand, runHook, signSlip, status, stopService, tempFolder, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
// A file the recorder has just written may be held open for a moment on
// Windows (a virus scanner reads each new file), so the test's own changes
// to it are tried again for up to ten seconds, as the recorder's are.
async function untilFree(step) {
  const deadline = Date.now() + 10000;
  for (let wait = 10; ; wait = Math.min(wait * 2, 200)) {
    try { return step(); } catch (e) {
      if (!['EPERM', 'EBUSY', 'EACCES'].includes(e.code) || Date.now() >= deadline) throw e;
      await new Promise((done) => setTimeout(done, wait));
    }
  }
}
const slipFingerprint = (slip) => fingerprint(fromBase64url(slip.payload));
const textFingerprint = async (text) => toBase64url(await sha256(utf8(text)));
const saveSlip = (slip) => {
  const file = join(tempFolder('provared-slip-'), 'slip.json');
  writeFileSync(file, JSON.stringify(slip));
  return file;
};
async function book(folder, passkeys, more = {}) {
  return checkBook(read(folder, 'book.jsonl'), { issuerKeys: passkeys, ...more });
}

// --- 1. "check" names no passkey for the person ---

test('check: with several permissions in the book, only the passkeys the person names are trusted', async () => {
  const { folder, passkey, agent } = await world([]);
  let service = await startService({ folder, port: 0 });
  const other = await developmentPasskey();
  await service.renew(await signSlip({ agentKeys: agent.keys, passkey: other }), { newPasskey: true });
  await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
  await service.close();
  const port = await freePort();
  const [mine, theirs] = [await thumbprint(passkey.key), await thumbprint(other.key)];
  // Named: both. Code 0.
  const both = await runCommand(['check', '--issuer', mine, '--issuer', theirs], { folder, port });
  assert.equal(both.code, 0, both.out + both.err);
  // Named: one. The other permission is a problem in the record. Code 2.
  const one = await runCommand(['check', '--issuer', mine], { folder, port });
  assert.equal(one.code, 2, one.out + one.err);
  // None named: both are shown as read from the book, and nothing is called named.
  const none = await runCommand(['check'], { folder, port });
  assert.equal(none.code, 1, none.out + none.err);
  assert.match(none.err, new RegExp(`passkey ${mine}`));
  assert.match(none.err, new RegExp(`passkey ${theirs}`));
  assert.doesNotMatch(none.out, /Checked against keys you named\? +yes/);
  // A kept slip file dropped in the folder changes nothing: "check" reads no slip file.
  writeFileSync(join(folder, `slip-${'A'.repeat(43)}.json`), read(folder, 'slip.json'));
  assert.equal((await runCommand(['check'], { folder, port })).code, 1);
  service = null;
});

// --- 2. the list of trusted passkeys ---

test('trust: the list is written at the first use and changed only by renew --new-passkey', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const list = () => JSON.parse(read(folder, 'trusted-passkeys.json')).passkeys;
    assert.deepEqual(list(), [await thumbprint(passkey.key)]);
    // The same passkey: nothing added.
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey }));
    assert.deepEqual(list(), [await thumbprint(passkey.key)]);
    // Another, at the person's word.
    const other = await developmentPasskey();
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey: other }), { newPasskey: true });
    assert.deepEqual(list(), [await thumbprint(passkey.key), await thumbprint(other.key)]);
    assert.deepEqual((await status(service.port)).trusted, list());
  } finally {
    await service.close();
  }
  // The first "use", by the command: the list begins with that permission's passkey.
  const fresh = tempFolder();
  const port = await freePort();
  try {
    const { makeAgentKeys } = await import('../recorder.mjs');
    const keys = await makeAgentKeys(fresh);
    const p = await developmentPasskey();
    const r = await runCommand(['use', saveSlip(await signSlip({ agentKeys: keys.keys, passkey: p }))], { folder: fresh, port });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(JSON.parse(read(fresh, 'trusted-passkeys.json')).passkeys, [await thumbprint(p.key)]);
  } finally {
    await stopService(port);
  }
});

test('trust: a permission written into the book and slip.json while the recorder is stopped stops it from starting', async () => {
  const { folder, agent } = await world([]);
  const first = await startService({ folder, port: 0 });
  await runHook(first.port, 'PostToolUse', 'Read', { file_path: 'a' });
  await first.close();
  const before = read(folder, 'book.jsonl');
  const evil = await developmentPasskey();
  const hostile = await signSlip({ agentKeys: agent.keys, passkey: evil, actions: ['provared.code.run', 'provared.data.delete'], never: [], purpose: 'Made by the agent' });
  appendFileSync(join(folder, 'book.jsonl'), entryLine({ slip: hostile }) + '\n');
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(hostile));
  await assert.rejects(startService({ folder, port: 0 }), /book holds a permission signed by a passkey that is not on the list/);
  // The line alone, with the person's slip.json left in place: the same.
  writeFileSync(join(folder, 'book.jsonl'), before + entryLine({ slip: hostile }) + '\n');
  await assert.rejects(startService({ folder, port: 0 }), /not on the list/);
});

test('trust: a book from a recorder that kept no list is taken where it has one passkey, and refused where it has more', async () => {
  const { folder, passkey, agent } = await world([]);
  let service = await startService({ folder, port: 0 });
  await service.close();
  // As an earlier version left it: no list.
  await untilFree(() => renameSync(join(folder, 'trusted-passkeys.json'), join(folder, 'old-list.json')));
  service = await startService({ folder, port: 0 });
  await service.close();
  assert.deepEqual(JSON.parse(read(folder, 'trusted-passkeys.json')).passkeys, [await thumbprint(passkey.key)], 'written for it');
  // Two passkeys in the book and no list: refused, with the way to write the list.
  const other = await developmentPasskey();
  service = await startService({ folder, port: 0 });
  await service.renew(await signSlip({ agentKeys: agent.keys, passkey: other }), { newPasskey: true });
  await service.close();
  await untilFree(() => renameSync(join(folder, 'trusted-passkeys.json'), join(folder, 'old-list-2.json')));
  await assert.rejects(startService({ folder, port: 0 }), /signed by 2 passkeys.*no list/s);
  // A list that cannot be read: refused, never taken as empty.
  await untilFree(() => writeFileSync(join(folder, 'trusted-passkeys.json'), '{"passkeys": "everyone"}'));
  await assert.rejects(startService({ folder, port: 0 }), /does not hold a list of passkey thumbprints/);
  // An empty list, and one with something that is not a thumbprint: refused the same way.
  await untilFree(() => writeFileSync(join(folder, 'trusted-passkeys.json'), '{"passkeys": []}'));
  await assert.rejects(startService({ folder, port: 0 }), /does not hold a list of passkey thumbprints/);
  const notOne = `{"passkeys": ["${await thumbprint(passkey.key)}", "not one"]}`;
  await untilFree(() => writeFileSync(join(folder, 'trusted-passkeys.json'), notOne));
  await assert.rejects(startService({ folder, port: 0 }), /does not hold a list of passkey thumbprints/);
});

// --- 3. is in naming.test (claude-code.test.mjs, "commands are named by what they do") ---

// --- 4. a call straddling a renewal, and calls asked at the same moment ---

test('a call allowed under one permission and taken while a renewal switched to the next is recorded under the one it was allowed under', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const call = { tool_use_id: 'toolu_push' };
    const pre = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'git push origin main' }, { more: call });
    assert.equal(pre.out, '', 'allowed under the first permission, which allows releases');
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, actions: ['provared.code.read', 'provared.code.run'], purpose: 'No more releases.' }));
    const post = await runHook(service.port, 'PostToolUse', 'Bash', { command: 'git push origin main' }, { more: call });
    assert.equal(post.code, 0, post.err);
    // A call asked after the renewal is under the new permission.
    await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' });
    const result = await book(folder, [await thumbprint(passkey.key)]);
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    assert.equal(result.summary.withinSlips, true, JSON.stringify(result.entries.flatMap((e) => e.breaches ?? [])));
    const stubs = result.entries.filter((e) => e.kind === 'stub');
    assert.equal(stubs[0].slip, await slipFingerprint(first));
    assert.equal(stubs[0].content.action, 'provared.code.release');
    assert.notEqual(stubs[1].slip, await slipFingerprint(first));
    // The writer for the permission in force carries on after it.
    assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'b' })).code, 0);
  } finally {
    await service.close();
  }
});

test('calls asked at the same moment count against a limit while they are allowed and not yet recorded: near a count limit no more are allowed than fit', async () => {
  // Before the change of F-112's round, all five were allowed (none was recorded yet), and the book showed three outside the permission.
  const { folder, passkey } = await world([{ action: 'provared.code.run', count: 2 }]);
  const service = await startService({ folder, port: 0 });
  try {
    const asked = await Promise.all([1, 2, 3, 4, 5].map((i) => runHook(service.port, 'PreToolUse', 'Bash', { command: `npm run t${i}` }, { more: { tool_use_id: `t${i}` } })));
    const allowed = asked.flatMap((r, i) => (r.out === '' ? [i + 1] : []));
    assert.equal(allowed.length, 2, 'two allowed: the limit has room for two');
    for (const r of asked.filter((x) => x.out !== '')) {
      assert.equal(r.decision.permissionDecision, 'deny');
      assert.match(r.decision.permissionDecisionReason, /\[over-count-limit\] 2 calls of this action \(provared\.code\.run\) allowed and not yet recorded would use the rest of what the permission allows \(2 in all\)/);
    }
    for (const i of allowed) await runHook(service.port, 'PostToolUse', 'Bash', { command: `npm run t${i}` }, { more: { tool_use_id: `t${i}` } });
    const result = await book(folder, [await thumbprint(passkey.key)]);
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.withinSlips, true, 'nothing outside the permission');
    assert.equal(result.summary.counts.stubs, 2);
  } finally {
    await service.close();
  }
});

test('requests are taken one at a time: no stub written while a renewal switches is lost', async () => {
  const { folder, passkey, agent } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const post = (path, body) => fetch(`http://127.0.0.1:${service.port}${path}`, { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
    const renewing = post('/renew', { slip: await signSlip({ agentKeys: agent.keys, passkey }) });
    const stubs = await Promise.all(Array.from({ length: 12 }, (_, i) => post('/record', { action: 'provared.code.read', details: [{ name: 'Read', sha256: 'A'.repeat(43) }], toolUseId: `r${i}` })));
    assert.ok(!(await renewing).error);
    assert.ok(stubs.every((s) => typeof s.fingerprint === 'string'), JSON.stringify(stubs));
    const result = await book(folder, [await thumbprint(passkey.key)]);
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.stubs, 12, 'every stub that was answered is in the book');
    assert.equal((await status(service.port)).entries, 14);
  } finally {
    await service.close();
  }
});

test('a renewal writes slip.json, the list and the book only once the new writer is open', async () => {
  const { folder, passkey, agent, slip } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const before = { slip: read(folder, 'slip.json'), book: read(folder, 'book.jsonl'), list: read(folder, 'trusted-passkeys.json') };
    // A permission that passes its own check, but repeats the unique number of the one in the book: the book with it has a problem, so no writer opens.
    const id = JSON.parse(new TextDecoder().decode(fromBase64url(slip.payload))).id;
    const other = await developmentPasskey();
    const twin = await signSlip({ agentKeys: agent.keys, passkey: other, id });
    await assert.rejects(service.renew(twin, { newPasskey: true }));
    assert.equal(read(folder, 'slip.json'), before.slip);
    assert.equal(read(folder, 'book.jsonl'), before.book);
    assert.equal(read(folder, 'trusted-passkeys.json'), before.list);
    assert.equal((await status(service.port)).slip, await slipFingerprint(slip), 'the writer before goes on');
    assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'a' })).code, 0);
  } finally {
    await service.close();
  }
  void passkey;
});

test('a permission whose passkey signature this device cannot check is not taken', async () => {
  const { agent, passkey } = await world([]);
  const slip = await signSlip({ agentKeys: agent.keys, passkey });
  await assert.rejects(checkNewSlip(slip, { agentKeys: agent.keys, withoutMethods: ['ES256'] }), /could not check the passkey's signature/);
  assert.equal((await checkNewSlip(slip, { agentKeys: agent.keys })).issuerKey, await thumbprint(passkey.key));
});

// --- 5. nothing in a call keeps its stub from being written ---

test('a failed call whose error text holds a broken character still leaves its stub', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const input = '{"session_id":"t","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"x","tool_input":{"command":"npm test"},"error":"output cut here \\ud83d","is_interrupt":false}';
    const r = await runHook(service.port, null, null, null, { input });
    assert.equal(r.code, 0, r.err);
    const result = await book(folder, [await thumbprint(passkey.key)]);
    const stub = result.entries.find((e) => e.kind === 'stub').content;
    assert.equal(stub.details[0].name, 'Bash (failed)');
    // The error as UTF-8, its broken character written as U+FFFD.
    assert.deepEqual(stub.details[1], { name: 'error', sha256: await textFingerprint('output cut here �') });
  } finally {
    await service.close();
  }
});

test('arguments that cannot be written in the one canonical form leave a stub naming the tool and the fallback form', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const big = '{"session_id":"t","hook_event_name":"PostToolUse","tool_name":"mcp__db__query","tool_use_id":"a","tool_input":{"n":1e400}}';
    const broken = '{"session_id":"t","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"b","tool_input":{"command":"x \\udc00"},"error":"e"}';
    assert.equal((await runHook(service.port, null, null, null, { input: big })).code, 0);
    assert.equal((await runHook(service.port, null, null, null, { input: broken })).code, 0);
    const long = 'mcp__server__' + 'x'.repeat(300);
    assert.equal((await runHook(service.port, 'PostToolUse', long, {})).code, 0);
    // Two calls that differ only in the sign of a number too large to hold, and one with the text "Infinity".
    const amount = (value) => `{"session_id":"t","hook_event_name":"PostToolUse","tool_name":"mcp__db__transfer","tool_use_id":"c","tool_input":{"amount":${value},"note":"\\ud800"}}`;
    for (const value of ['1e400', '-1e400', '"Infinity"']) assert.equal((await runHook(service.port, null, null, null, { input: amount(value) })).code, 0);
    const result = await book(folder, [await thumbprint(passkey.key)]);
    const stubs = result.entries.filter((e) => e.kind === 'stub').map((e) => e.content);
    // 1e400 is read as Infinity; the fallback form writes it as it was sent.
    assert.deepEqual(stubs[0].details, [{ name: 'mcp__db__query (arguments in the fallback form)', sha256: await textFingerprint('{"n":1e400}') }]);
    assert.deepEqual(stubs[1].details[0], { name: 'Bash (failed; arguments in the fallback form)', sha256: await textFingerprint(JSON.stringify({ command: 'x \udc00' })) });
    assert.equal([...stubs[2].details[0].name].length, 120, 'a long tool name is cut to fit');
    const [plus, minus, text] = stubs.slice(3, 6).map((s) => s.details[0].sha256);
    assert.equal(plus, await textFingerprint('{"amount":1e400,"note":"\\ud800"}'));
    assert.equal(minus, await textFingerprint('{"amount":-1e400,"note":"\\ud800"}'));
    assert.equal(text, await textFingerprint('{"amount":"Infinity","note":"\\ud800"}'));
    assert.equal(new Set([plus, minus, text]).size, 3, 'no two of the three share a fingerprint');
  } finally {
    await service.close();
  }
});

// --- 7. long books, and calls that wait ---

test('saving appends at a cost that does not grow with the book; a file changed by someone else is compared whole', () => {
  const folder = tempFolder('provared-save-');
  const path = join(folder, 'book.jsonl');
  const save = bookSaver(folder);
  let text = 'a'.repeat(5000) + '\nœ✓\n';
  save(text);
  text += 'second\n';
  save(text);
  assert.equal(readFileSync(path, 'utf8'), text);
  // An edit in the middle that keeps the size and the end: the saver appends without reading the whole file, so the edit stays.
  const edited = 'b' + readFileSync(path, 'utf8').slice(1);
  writeFileSync(path, edited);
  text += 'third\n';
  save(text);
  assert.equal(readFileSync(path, 'utf8'), edited + 'third\n');
  // A file grown or cut by someone else: compared whole, and replaced by the book.
  appendFileSync(path, 'stranger\n');
  text += 'fourth\n';
  save(text);
  assert.equal(readFileSync(path, 'utf8'), text);
  assert.ok(statSync(path).size > 5000);
});

test('saving a book that does not go on from the one last saved replaces the file, and appends nothing', () => {
  const folder = tempFolder('provared-save-');
  const path = join(folder, 'book.jsonl');
  const save = bookSaver(folder);
  const start = 'a'.repeat(5000) + '\n';
  save(start + 'a permission that was not taken\n');
  // The recorder's own book, longer than what was saved but not going on from it (a renewal that failed).
  const book = start + 'the stub of the next call, a little longer\n';
  save(book);
  assert.equal(readFileSync(path, 'utf8'), book);
  save(book + 'more\n');
  assert.equal(readFileSync(path, 'utf8'), book + 'more\n');
});

test('a file that cannot be written leaves no temporary file behind, and the old file as it was', () => {
  const folder = tempFolder('provared-replace-');
  const path = join(folder, 'book.jsonl');
  writeFileSync(path, 'the old book\n');
  // A write that stops part of the way, as on a full disk.
  const partial = (file, text) => {
    writeFileSync(file, text.slice(0, 5));
    throw Object.assign(new Error('no space left on the device'), { code: 'ENOSPC' });
  };
  assert.throws(() => replaceFile(path, 'the new book\n', { write: partial }), /no space left/);
  assert.equal(existsSync(`${path}.tmp`), false, 'no temporary file left behind');
  assert.equal(readFileSync(path, 'utf8'), 'the old book\n');
  // A replacement that is refused for good: the same.
  const refused = () => { throw Object.assign(new Error('refused'), { code: 'ENOTDIR' }); };
  assert.throws(() => replaceFile(path, 'the new book\n', { rename: refused }), /refused/);
  assert.equal(existsSync(`${path}.tmp`), false, 'no temporary file left behind');
  assert.equal(readFileSync(path, 'utf8'), 'the old book\n');
  // And where nothing goes wrong, the file is replaced.
  replaceFile(path, 'the new book\n');
  assert.equal(readFileSync(path, 'utf8'), 'the new book\n');
  assert.equal(existsSync(`${path}.tmp`), false);
});

test('the stub of a call that was taken is written even where its hook gave up waiting', async () => {
  const { folder, passkey } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    // A seal holds the service for about a second and a half (SLH-DSA).
    const sealing = service.seal();
    const given = { action: 'provared.code.read', details: [{ name: 'Read', sha256: 'A'.repeat(43) }], toolUseId: 'gave-up' };
    await assert.rejects(fetch(`http://127.0.0.1:${service.port}/record`, { method: 'POST', body: JSON.stringify(given), signal: AbortSignal.timeout(150) }));
    await sealing;
    await new Promise((r) => setTimeout(r, 500));
    const result = await book(folder, [await thumbprint(passkey.key)], { sealKeys: [(await status(service.port)).sealer] });
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.counts.stubs, 1, 'the action was taken, so its stub is written, late');
  } finally {
    await service.close();
  }
});

test('calls caught by a renewal are each recorded under the permission they were allowed under, with no further reading of the book', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const ids = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6'];
    for (const id of ids) {
      const pre = await runHook(service.port, 'PreToolUse', 'Read', { file_path: id }, { more: { tool_use_id: id } });
      assert.equal(pre.out, '', 'allowed');
    }
    const before = service.readings;
    await service.renew(await signSlip({ agentKeys: agent.keys, passkey, purpose: 'renewed' }));
    assert.equal(service.readings, before + 1, 'the renewal opens one writer on the book');
    const posts = await Promise.all(ids.map((id) => runHook(service.port, 'PostToolUse', 'Read', { file_path: id }, { more: { tool_use_id: id } })));
    for (const p of posts) assert.equal(p.code, 0, p.err);
    assert.equal(service.readings, before + 1, 'the six stubs under the permission before cost no further reading');
    // A call asked after the renewal is under the new permission, as is everything the writer in force does next.
    assert.equal((await runHook(service.port, 'PostToolUse', 'Read', { file_path: 'after' })).code, 0);
    const result = await book(folder, [await thumbprint(passkey.key)]);
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    const stubs = result.entries.filter((e) => e.kind === 'stub');
    const fp1 = await slipFingerprint(first);
    assert.equal(stubs.filter((e) => e.slip === fp1).length, 6);
    assert.notEqual(stubs.at(-1).slip, fp1);
    assert.equal((await status(service.port)).entries, 1 + 1 + 6 + 1, 'two slips, seven stubs');
  } finally {
    await service.close();
  }
});

// Each step waits for an event, not for a length of time: the seal holds the
// service because the first signature check it makes is held back until the
// test lets it go; the renewal is given up only once the service has read it
// whole and it waits its turn; and the seal is let go only once the service
// has seen the caller go.
// An event the test waits for that has not come within a minute fails the test, in words, rather than leaving it waiting.
const NOT_CAME = Symbol('not came');
async function inTime(promise, what) {
  let timer;
  const value = await Promise.race([promise, new Promise((done) => { timer = setTimeout(() => done(NOT_CAME), 60000); })]);
  clearTimeout(timer);
  if (value === NOT_CAME) assert.fail(`Waited a minute and ${what} did not happen.`);
  return value;
}
test('a renewal whose caller gave up waiting is not made', async () => {
  const { folder, passkey, agent, slip: first } = await world([]);
  const second = await signSlip({ agentKeys: agent.keys, passkey, purpose: 'renewed' });
  const service = await startService({ folder, port: 0 });
  const subtle = globalThis.crypto.subtle;
  const verify = subtle.verify;
  const emit = http.Server.prototype.emit;
  let letGo;
  const gate = new Promise((ok) => {
    letGo = ok;
  });
  try {
    // The next signature check, the seal's own, waits for the gate; every other check goes on as before.
    let reached;
    const holding = new Promise((ok) => {
      reached = ok;
    });
    let armed = true;
    subtle.verify = async function (...args) {
      if (armed) {
        armed = false;
        reached();
        await gate;
      }
      return verify.apply(this, args);
    };
    const sealing = service.seal();
    const settled = sealing.then(() => 'sealed', () => 'sealed');
    await inTime(holding, "the seal's first signature check");
    // The renewal, once the service has read its body: its turn is asked for in the same round, before setImmediate runs.
    let arrived;
    const waiting = new Promise((ok) => {
      arrived = ok;
    });
    http.Server.prototype.emit = function (...args) {
      const [event, req, res] = args;
      if (event === 'request' && req.url === '/renew') req.once('end', () => setImmediate(() => arrived(res)));
      return emit.apply(this, args);
    };
    const giveUp = new AbortController();
    const asked = fetch(`http://127.0.0.1:${service.port}/renew`, { method: 'POST', body: JSON.stringify({ slip: second }), signal: giveUp.signal });
    const answered = asked.then(() => 'answered', () => 'given up');
    const res = await inTime(Promise.race([waiting, answered]), 'the service reading the renewal');
    assert.notEqual(res, 'answered', 'the renewal was answered while the seal held the service');
    assert.equal(await Promise.race([settled, Promise.resolve('holding')]), 'holding', 'the seal holds the service while the renewal waits');
    const gone = once(res, 'close');
    giveUp.abort();
    await assert.rejects(asked);
    await inTime(gone, 'the service seeing the caller go');
    letGo();
    await sealing;
    // A question asked after the renewal waits its turn behind it, so once it is answered the renewal's turn is over.
    assert.equal((await runHook(service.port, 'PreToolUse', 'Read', { file_path: 'after' })).out, '', 'allowed');
    assert.equal((await status(service.port)).slip, await slipFingerprint(first), 'the person was told it failed, and it was not made');
  } finally {
    letGo();
    subtle.verify = verify;
    http.Server.prototype.emit = emit;
    await service.close();
  }
});

test('the seal command shows the recorder\'s error and ends with a code that is not 0', async () => {
  const { createServer: httpServer } = await import('node:http');
  // A recorder that answers its status, and refuses to seal.
  const refusing = httpServer((req, res) => {
    req.resume();
    res.writeHead(req.url === '/status' ? 200 : 500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(req.url === '/status' ? { slip: 'x' } : { error: 'the recorder could not seal: a made-up reason' }));
  });
  await new Promise((r) => refusing.listen(0, '127.0.0.1', r));
  try {
    const r = await runCommand(['seal'], { folder: tempFolder(), port: refusing.address().port });
    assert.equal(r.code, 1, r.out);
    assert.match(r.err, /The book was not sealed: the recorder could not seal: a made-up reason/);
    assert.doesNotMatch(r.out, /undefined/);
  } finally {
    await new Promise((r) => refusing.close(r));
  }
});

test('the hook says "not written" only where the recorder refused or was not there', async () => {
  // A recorder that takes the request and then drops the connection: the stub may or may not have been written.
  const dropping = createServer((socket) => socket.once('data', () => socket.destroy()));
  await new Promise((r) => dropping.listen(0, '127.0.0.1', r));
  try {
    const r = await runHook(dropping.address().port, 'PostToolUse', 'Read', { file_path: 'a' });
    assert.equal(r.code, 2);
    assert.match(r.err, /did not confirm the stub/);
    assert.doesNotMatch(r.err, /was not written/);
  } finally {
    await new Promise((r) => dropping.close(r));
  }
  // Nothing on the port: known not written.
  const r = await runHook(await freePort(), 'PostToolUse', 'Read', { file_path: 'a' });
  assert.match(r.err, /was not written/);
});

// --- 8. init on settings files as people have them ---

function project(text) {
  const dir = tempFolder('provared-project-');
  mkdirSync(join(dir, '.claude'));
  if (text !== undefined) writeFileSync(join(dir, '.claude', 'settings.local.json'), text);
  return { dir, path: join(dir, '.claude', 'settings.local.json') };
}

test('init: a settings file with a byte-order mark is read, and keeps its mark', () => {
  const { dir, path } = project('﻿{"permissions":{"allow":["Bash(npm test)"]}}');
  const written = writeHooks(dir);
  assert.equal(written.added, 4);
  const text = readFileSync(path, 'utf8');
  assert.ok(text.startsWith('﻿'));
  assert.deepEqual(JSON.parse(text.slice(1)).permissions, { allow: ['Bash(npm test)'] });
});

test('init: a settings file that already does what it would write is left byte for byte as it is', () => {
  const ours = hookSettings();
  const compact = JSON.stringify({ hooks: ours });
  const { dir, path } = project(compact);
  const written = writeHooks(dir);
  assert.equal(written.added + written.replaced, 0);
  assert.equal(readFileSync(path, 'utf8'), compact);
});

test('init: a longer time-out the person set is kept, and our hook written as one command line is replaced, not doubled', () => {
  const ours = hookSettings();
  const longer = { ...ours.PreToolUse[0].hooks[0], timeout: 120 };
  const line = { type: 'command', command: `node "${ours.PostToolUse[0].hooks[0].args[1].split('/').join('\\')}"`, timeout: 90 };
  const { dir, path } = project(JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [longer] }], PostToolUse: [{ matcher: '*', hooks: [line] }] } }));
  const written = writeHooks(dir);
  assert.equal(written.present, 1, 'PreToolUse is there, with a longer time-out');
  assert.equal(written.added, 2, 'SessionStart and PostToolUseFailure');
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  assert.deepEqual(settings.hooks.PreToolUse, [{ matcher: '*', hooks: [longer] }]);
  assert.deepEqual(settings.hooks.PostToolUse, [{ matcher: '*', hooks: [{ ...ours.PostToolUse[0].hooks[0], timeout: 90 }] }]);
  assert.equal(written.replaced, 1);
});

test('init: a hook of the person\'s own that only mentions this recorder\'s files stays as it is', () => {
  const ours = hookSettings();
  const hookPath = ours.PreToolUse[0].hooks[0].args[1];
  const recorderPath = ours.SessionStart[0].hooks[0].args[1];
  const mine = [
    { type: 'command', command: `node "${hookPath}" && powershell -File C:/me/notify.ps1` },
    { type: 'command', command: `node "${hookPath}.backup"` },
    { type: 'command', command: 'node', args: [hookPath, '--verbose'] },
  ];
  const status = { type: 'command', command: `node "${recorderPath}" status > C:/me/recorder-status.txt` };
  const { dir, path } = project(JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: mine }], SessionStart: [{ hooks: [status] }] } }));
  const written = writeHooks(dir);
  assert.equal(written.replaced, 0, 'nothing of the person\'s is taken for this recorder\'s own');
  assert.equal(written.added, 4);
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  assert.deepEqual(settings.hooks.PreToolUse[0], { matcher: 'Bash', hooks: mine }, 'every one of the person\'s hooks stays, as it was');
  assert.deepEqual(settings.hooks.SessionStart[0], { hooks: [status] });
  assert.deepEqual(settings.hooks.PreToolUse[1], ours.PreToolUse[0]);
  // A hook is pointed out where its command says "provared": here through the
  // folder's path, so the number depends on where the repository sits.
  const naming = [...mine, status].filter((h) => /provared/i.test(JSON.stringify([h.command, h.args]))).length;
  assert.equal(written.others.length, naming, 'each one that names Provared is pointed out');
  // This recorder's own command, written as one line with nothing more, is its own: replaced, not doubled.
  const again = project(JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: `node "${recorderPath}" ensure` }] }] } }));
  assert.equal(writeHooks(again.dir).replaced, 1);
  assert.deepEqual(JSON.parse(readFileSync(again.path, 'utf8')).hooks.SessionStart, ours.SessionStart);
});

test('init: "disableAllHooks" is pointed out', async () => {
  const { dir } = project('{"disableAllHooks": true}');
  assert.equal(writeHooks(dir).switchedOff, true);
  const folder = tempFolder();
  const r = await runCommand(['init'], { folder, port: await freePort(), cwd: dir });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /"disableAllHooks": true, so Claude Code runs no hook/);
  assert.ok(existsSync(join(folder, 'agent-keys.jwk')));
});
