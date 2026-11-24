// "init" and the words of the waiting state. In a fresh folder "init" makes
// the keys, writes the hooks, starts the recorder in the background as
// "ensure" does, so that it waits for the agent's first permission, and says
// what to do next: the application, its book's one line, the approval in the
// signing window, then "admit-passkey" with the thumbprint pasted from the
// signing window and a typed "yes". It prints the fingerprint of the agent's
// key set, which the signing window asks for, and no link; "init --link"
// prints the link as before. Where the folder is not fresh it starts
// nothing and changes nothing in the record; where the start fails it says
// so and names "ensure". The words of "ensure", "status", the start of a
// session and the hook's refusal while the recorder waits say the same
// steps. Every test works in a temporary folder and on a port of its own, and
// stops any recorder it started.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { createServer as createTcpServer } from 'node:net';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

const { keySetFingerprint } = await import('provared');
const { loadAgentKeys, startService } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freePort, freshWorld, runCommand, runHook, status, stopService, tempFolder, world } = await import('./world.mjs');

/** The status of what answers on the port, asked again until "ms" have passed on the monotonic clock; null where nothing answers. */
async function answersWithin(port, ms) {
  for (const until = performance.now() + ms; performance.now() < until;) {
    try {
      return await status(port);
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  return null;
}

/** Every file in the folder, by name, with its bytes as base64 (a folder within it by its name only). */
function filesIn(folder) {
  const out = {};
  for (const name of readdirSync(folder).sort()) {
    const path = join(folder, name);
    out[name] = statSync(path).isDirectory() ? 'a folder' : readFileSync(path).toString('base64');
  }
  return out;
}

const fingerprintLine = (out) => (out.match(/The fingerprint of the agent's key set: ([A-Za-z0-9_-]{43})/) ?? [])[1];
const LINK = /https:\/\/sign\.prova\.red\/#permission=/;

/** The steps of the waiting state, as each of the recorder's words must give them. */
function saysTheSteps(words) {
  assert.match(words, /Open the application, make a book/, words);
  assert.match(words, /one line/, words);
  assert.match(words, /Approve what it may do/, words);
  assert.match(words, /Keep the signing window open/, words);
  assert.match(words, /admit-passkey <the thumbprint>/, words);
  assert.match(words, /thumbprint the signing window shows/, words);
  assert.match(words, /at least its first 16 characters/, words);
  assert.match(words, /type yes/, words);
}

test('"init" in a fresh folder leaves a recorder that waits, prints the fingerprint and the steps of the waiting state, and no link', async () => {
  const folder = join(tempFolder(), 'claude-code'); // the folder does not exist yet
  const project = tempFolder('provared-project-');
  const port = await freePort();
  try {
    const r = await runCommand(['init'], { folder, port, cwd: project });
    assert.equal(r.code, 0, `${r.out}\n${r.err}`);
    assert.match(r.out, /The hooks are in /);
    const st = await status(port);
    assert.equal(st.waiting, true, 'the recorder waits for its first permission');
    assert.equal(st.folder, folder);
    assert.match(r.out, new RegExp(`The recorder is running on 127\\.0\\.0\\.1:${port}, and waits for the agent's first permission`));
    // The fingerprint, as the library works it out for the agent's keys, and what the signing window asks of it.
    const expected = await keySetFingerprint((await loadAgentKeys(folder)).keys);
    assert.equal(fingerprintLine(r.out), expected);
    assert.equal(st.agentKeySet, expected);
    assert.match(r.out, /When the signing window asks for the fingerprint of the agent's key set, paste this one there/);
    saysTheSteps(r.out);
    // No link: "init --link" prints it.
    assert.doesNotMatch(r.out, LINK);
    assert.match(r.out, /init --link/);
    assert.doesNotMatch(r.err, /The recorder is running and waits/, 'ensure\'s own words are not said twice');
  } finally {
    await stopService(port);
  }
});

test('"init" run twice in a fresh folder leaves one recorder, the first, and says that it waits', async () => {
  const w = await freshWorld();
  const project = tempFolder('provared-project-');
  const port = await freePort();
  try {
    const first = await runCommand(['init', '--no-hooks'], { folder: w.folder, port, cwd: project });
    assert.equal(first.code, 0, `${first.out}\n${first.err}`);
    const before = await status(port);
    assert.equal(before.waiting, true);
    const again = await runCommand(['init', '--no-hooks'], { folder: w.folder, port, cwd: project });
    assert.equal(again.code, 0, `${again.out}\n${again.err}`);
    assert.match(again.out, /waits for the agent's first permission/);
    saysTheSteps(again.out);
    const after = await status(port);
    assert.equal(after.waiting, true);
    assert.equal(after.started, before.started, 'the same recorder: not started again, nor replaced');
    assert.equal(fingerprintLine(again.out), fingerprintLine(first.out), 'the same keys');
  } finally {
    await stopService(port);
  }
});

test('"init --link" prints the link, the fingerprint and the "use" step, and starts the recorder that waits too; it combines with --no-hooks; any other argument prints the usage and writes nothing', async () => {
  const folder = join(tempFolder(), 'claude-code');
  const project = tempFolder('provared-project-');
  const port = await freePort();
  try {
    const wrong = await runCommand(['init', '--link', '--no-hook'], { folder, port, cwd: project });
    assert.equal(wrong.code, 2);
    assert.match(wrong.out, /Usage: /);
    assert.match(wrong.out, /--link/);
    assert.ok(!existsSync(join(folder, 'agent-keys.jwk')), 'nothing was written');
    assert.equal(await answersWithin(port, 500), null, 'nothing was started');
    const r = await runCommand(['init', '--no-hooks', '--link'], { folder, port, cwd: project });
    assert.equal(r.code, 0, `${r.out}\n${r.err}`);
    assert.match(r.out, /No hooks were written \(--no-hooks\)/);
    assert.ok(!existsSync(join(project, '.claude')), 'no hooks');
    const link = r.out.split('\n').map((l) => l.trim()).find((l) => LINK.test(l));
    assert.ok(link, r.out);
    const fp = await keySetFingerprint((await loadAgentKeys(folder)).keys);
    assert.equal(fingerprintLine(r.out), fp);
    assert.match(r.out, /use <the saved file>/);
    assert.equal((await status(port)).waiting, true, 'both ways work: the recorder waits as well');
    // The other order of the two switches, with the recorder running: the same.
    const again = await runCommand(['init', '--link', '--no-hooks'], { folder, port, cwd: project });
    assert.equal(again.code, 0, `${again.out}\n${again.err}`);
    assert.match(again.out, LINK);
  } finally {
    await stopService(port);
  }
});

test('"init" where a permission is in force starts no recorder that waits, changes nothing in the folder, and says to run "ensure"', async () => {
  const w = await world([]);
  // The full recorder has run once here: the book, the list of trusted passkeys, the recorder's keys and the feed's token are there.
  const once = await startService({ folder: w.folder, port: 0 });
  await once.close();
  const project = tempFolder('provared-project-');
  const port = await freePort();
  const before = filesIn(w.folder);
  assert.ok(before['book.jsonl'] && before['trusted-passkeys.json'], Object.keys(before).join(', '));
  try {
    const r = await runCommand(['init', '--no-hooks'], { folder: w.folder, port, cwd: project });
    assert.equal(r.code, 0, `${r.out}\n${r.err}`);
    assert.match(r.out, /A permission is in place here already \(slip\.json\)/);
    assert.match(r.out, /ensure/);
    assert.match(r.out, /nothing in the record was changed/);
    assert.doesNotMatch(r.out, /waits for the agent's first permission/);
    assert.doesNotMatch(r.out, LINK);
    assert.equal(await answersWithin(port, 1500), null, 'nothing was started');
    assert.deepEqual(filesIn(w.folder), before, 'every file as it was');
    // With the full recorder running: it is said, and it runs on as it was.
    const running = await startService({ folder: w.folder, port });
    try {
      const st = await status(port);
      const r2 = await runCommand(['init', '--no-hooks'], { folder: w.folder, port, cwd: project });
      assert.equal(r2.code, 0, `${r2.out}\n${r2.err}`);
      assert.match(r2.out, /the recorder runs with it/);
      const st2 = await status(port);
      assert.equal(st2.waiting, undefined);
      assert.equal(st2.started, st.started);
      assert.equal(st2.entries, st.entries, 'nothing written to the book');
    } finally {
      await running.close();
    }
  } finally {
    await stopService(port);
  }
});

test('"init" in a folder that is not fresh and holds no permission names what is there, starts nothing and points to "use"', async () => {
  const w = await freshWorld();
  const { writeFileSync } = await import('node:fs');
  writeFileSync(join(w.folder, 'trusted-passkeys.json'), JSON.stringify({ passkeys: ['A'.repeat(43)] }));
  const before = filesIn(w.folder);
  const port = await freePort();
  try {
    const r = await runCommand(['init', '--no-hooks'], { folder: w.folder, port, cwd: tempFolder('provared-project-') });
    assert.equal(r.code, 0, `${r.out}\n${r.err}`);
    assert.match(r.out, /holds trusted-passkeys\.json, so it is not fresh/);
    assert.match(r.out, /use <the saved file>/);
    assert.match(r.out, /nothing in the record was changed/);
    assert.equal(await answersWithin(port, 1500), null, 'nothing was started');
    assert.deepEqual(filesIn(w.folder), before);
  } finally {
    await stopService(port);
  }
});

test('"init" where another recorder answers on the port says that the start failed and names "ensure"; the keys and hooks stay', async () => {
  const other = tempFolder('provared-cc-other-');
  // A recorder for another folder, as its status gives it.
  const stand = createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ waiting: true, version: 'stand-in', folder: other }));
  });
  await new Promise((r) => stand.listen(0, '127.0.0.1', r));
  const port = stand.address().port;
  const folder = join(tempFolder(), 'claude-code');
  const project = tempFolder('provared-project-');
  try {
    const r = await runCommand(['init'], { folder, port, cwd: project });
    assert.equal(r.code, 1, `${r.out}\n${r.err}`);
    assert.match(r.out, /The recorder was not started/);
    assert.match(r.out, /not the recorder of this folder/);
    assert.match(r.out, /ensure/);
    assert.doesNotMatch(r.out, /is running on 127/);
    assert.ok(existsSync(join(folder, 'agent-keys.jwk')), 'the keys stay');
    assert.ok(existsSync(join(project, '.claude', 'settings.local.json')), 'the hooks stay');
    assert.ok(fingerprintLine(r.out));
  } finally {
    stand.closeAllConnections();
    await new Promise((r) => stand.close(r));
  }
});

test('"init" where the port is held by something that does not answer as a recorder says that the start failed and names "ensure"', { timeout: 60000 }, async () => {
  const held = createTcpServer((socket) => socket.destroy());
  await new Promise((r) => held.listen(0, '127.0.0.1', r));
  const port = held.address().port;
  const folder = join(tempFolder(), 'claude-code');
  try {
    const r = await runCommand(['init', '--no-hooks'], { folder, port, cwd: tempFolder('provared-project-') });
    assert.equal(r.code, 1, `${r.out}\n${r.err}`);
    assert.match(r.out, /The recorder was not started/);
    assert.match(r.out, /did not answer/);
    assert.match(r.out, /ensure/);
    assert.ok(existsSync(join(folder, 'agent-keys.jwk')), 'the keys stay');
  } finally {
    await new Promise((r) => held.close(r));
  }
});

test('"ensure", "status" and the start of a session say the steps of the waiting state; the start of a session starts the recorder that waits in a fresh folder', async () => {
  const w = await freshWorld();
  const port = await freePort();
  try {
    // The start of a session, with nothing running: the recorder that waits is started, and the steps said.
    const s = await runCommand(['session-start'], { folder: w.folder, port });
    assert.equal(s.code, 0, `${s.out}\n${s.err}`);
    const said = JSON.parse(s.out);
    assert.equal(said.systemMessage, said.hookSpecificOutput.additionalContext);
    assert.match(said.systemMessage, /waits for its first permission/);
    saysTheSteps(said.systemMessage);
    assert.doesNotMatch(said.systemMessage, /no permission has been signed for this agent yet, so the recorder is not running/);
    assert.equal((await status(port)).waiting, true);
    const e = await runCommand(['ensure'], { folder: w.folder, port });
    assert.equal(e.code, 0, `${e.out}\n${e.err}`);
    assert.match(e.err, /The recorder is running and waits for its first permission: every tool call is refused/);
    saysTheSteps(e.err);
    assert.match(e.err, /keys" prints it again/);
    const st = await runCommand(['status'], { folder: w.folder, port });
    assert.equal(st.code, 0, `${st.out}\n${st.err}`);
    assert.equal(JSON.parse(st.out).waiting, true, 'the status itself is still JSON');
    saysTheSteps(st.err);
  } finally {
    await stopService(port);
  }
});

test('a tool call while the recorder waits is refused with the steps of the waiting state, not as outside a permission', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0 });
  try {
    const r = await runHook(waiting.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { env: { PROVARED_CLAUDE_CODE_DIR: w.folder } });
    assert.equal(r.decision.permissionDecision, 'deny');
    const words = r.decision.permissionDecisionReason;
    assert.match(words, /no permission has been signed for this agent yet/);
    assert.match(words, /waits for the first one/);
    assert.doesNotMatch(words, /outside the permission the person signed/);
    saysTheSteps(words);
  } finally {
    await waiting.close();
  }
});

test('a tool call with no recorder running: with no keys, it points to init, which starts the recorder; with the keys there and no permission, to ensure', async () => {
  const empty = join(tempFolder(), 'claude-code');
  const port = await freePort();
  const r = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' }, { env: { PROVARED_CLAUDE_CODE_DIR: empty } });
  assert.equal(r.decision.permissionDecision, 'deny');
  assert.match(r.decision.permissionDecisionReason, /recorder\.mjs"? init/);
  assert.match(r.decision.permissionDecisionReason, /starts the recorder/);
  const w = await freshWorld();
  const r2 = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' }, { env: { PROVARED_CLAUDE_CODE_DIR: w.folder } });
  assert.equal(r2.decision.permissionDecision, 'deny');
  assert.match(r2.decision.permissionDecisionReason, /recorder\.mjs"? ensure/);
  assert.doesNotMatch(r2.decision.permissionDecisionReason, /recorder\.mjs"? init/);
});
