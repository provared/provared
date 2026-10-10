// The recorder beside Claude Code: the hook run as Claude Code runs it,
// against the service on a free port, under a slip signed with the
// library's development stand-in for a passkey.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assembleSlip, checkBook, formatTime, prepareSlip } from '../../../src/index.js';
import { developmentPasskey } from '../../../src/dev.js';
import { actionFor, commandAction } from '../actions.mjs';
import { loadRecorderKeys, loadSlip, makeAgentKeys, startService } from '../recorder.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const hook = join(here, '..', 'hook.mjs');

function runHook(port, event, toolName, toolInput) {
  // The hook is run as Claude Code runs it, as a separate process with its JSON on standard input.
  // It is awaited, not waited for, so that the service in this process can answer it.
  const input = JSON.stringify({ session_id: 'test', hook_event_name: event, tool_name: toolName, tool_input: toolInput, tool_use_id: 'toolu_1', cwd: here });
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', hook], { env: { ...process.env, PROVARED_CLAUDE_CODE_PORT: String(port) } });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => resolve({ code, out: out.trim(), err: err.trim(), decision: out.trim() ? JSON.parse(out).hookSpecificOutput : null }));
    child.stdin.end(input);
  });
}

async function world(limits = [{ action: 'provared.code.run', count: 2 }]) {
  const folder = mkdtempSync(join(tmpdir(), 'provared-cc-'));
  const agent = await makeAgentKeys(folder);
  const passkey = await developmentPasskey();
  const now = Date.now();
  const prepared = await prepareSlip({
    issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'A coding agent', keys: agent.keys },
    actions: ['provared.code.read', 'provared.code.change', 'provared.code.run', 'provared.code.release', 'provared.web.read', 'provared.agent.instruct'],
    limits,
    never: ['destroys'],
    with: [],
    validFrom: formatTime(now - 60000),
    validUntil: formatTime(now + 3600000),
    purpose: 'Test the recorder beside a coding agent.',
  });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(slip));
  return { folder, passkey };
}

test('tool calls are named from the shared list, by the hook', () => {
  assert.equal(actionFor('Read', { file_path: 'a' }), 'provared.code.read');
  assert.equal(actionFor('Edit', {}), 'provared.code.change');
  assert.equal(actionFor('WebFetch', {}), 'provared.web.read');
  assert.equal(actionFor('Agent', {}), 'provared.agent.instruct');
  assert.equal(actionFor('Bash', { command: 'npm test' }), 'provared.code.run');
  assert.equal(actionFor('mcp__example__search', {}), 'provared.code.run');
  assert.equal(actionFor('AskUserQuestion', {}), null);
  assert.equal(actionFor('TodoWrite', {}), null);
  assert.equal(commandAction('rm -rf dist'), 'provared.data.delete');
  assert.equal(commandAction('cd x && rm file'), 'provared.data.delete');
  assert.equal(commandAction('Remove-Item -Recurse build'), 'provared.data.delete');
  assert.equal(commandAction('git push --force origin main'), 'provared.data.delete');
  assert.equal(commandAction('git reset --hard HEAD~1'), 'provared.data.delete');
  assert.equal(commandAction('git push origin main'), 'provared.code.release');
  assert.equal(commandAction('npm.cmd publish --access public'), 'provared.code.release');
  assert.equal(commandAction('gh release create v1'), 'provared.code.release');
  assert.equal(commandAction('git status && npm test'), 'provared.code.run');
  assert.equal(commandAction('echo "rm is a word"'), 'provared.code.run');
  assert.equal(commandAction(undefined), 'provared.code.run');
});

test('the hook asks before, records after, refuses outside the slip, and the book checks', async () => {
  const { folder, passkey } = await world();
  const service = await startService({ folder, port: 0 });
  const port = service.port;
  try {
    // Within the slip: nothing is said before, and a stub is written after.
    let r = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, '');
    r = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' });
    assert.equal(r.code, 0, r.err);
    r = await runHook(port, 'PostToolUse', 'Read', { file_path: 'README.md' });
    assert.equal(r.code, 0, r.err);
    // A deletion: the slip forbids the kind "destroys" and does not name the action.
    r = await runHook(port, 'PreToolUse', 'Bash', { command: 'rm -rf node_modules' });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.decision.permissionDecision, 'deny');
    assert.match(r.decision.permissionDecisionReason, /outside the permission/);
    assert.match(r.decision.permissionDecisionReason, /\[action-not-allowed\]|\[prohibited\]/);
    // The second run is within the count; the third would be over it.
    r = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm run check' });
    assert.equal(r.code, 0, r.err);
    r = await runHook(port, 'PreToolUse', 'Bash', { command: 'node tools/x.mjs' });
    assert.equal(r.decision.permissionDecision, 'deny');
    assert.match(r.decision.permissionDecisionReason, /\[over-count-limit\]/);
    // A call that is not recorded: nothing is said, and nothing is written.
    r = await runHook(port, 'PreToolUse', 'AskUserQuestion', { questions: [] });
    assert.equal(r.code, 0);
    assert.equal(r.out, '');
    // Sealed, then checked as a reader would check it.
    const sealed = await service.seal();
    const status = await (await fetch(`http://127.0.0.1:${port}/status`)).json();
    assert.equal(status.entries, 5, 'the slip, three stubs and a seal');
    assert.equal(sealed.entries, 5);
    const book = readFileSync(join(folder, 'book.jsonl'), 'utf8');
    const { issuerKey } = await loadSlip(folder);
    const result = await checkBook(book, { issuerKeys: [issuerKey], sealKeys: [status.sealer] });
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    assert.equal(result.summary.withinSlips, true);
    assert.equal(result.summary.counts.stubs, 3);
    assert.equal(result.summary.counts.seals, 1);
    const stubs = result.entries.filter((e) => e.kind === 'stub');
    assert.deepEqual(stubs.map((e) => e.content.action), ['provared.code.run', 'provared.code.read', 'provared.code.run']);
    assert.equal(stubs[0].content.details[0].name, 'Bash');
    assert.match(stubs[0].content.details[0].sha256, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(passkey.rpId, 'localhost');
  } finally {
    await service.close();
  }
});

test('the service keeps the book on disk and opens it again; its keys are kept as files', async () => {
  const { folder } = await world([]);
  let service = await startService({ folder, port: 0 });
  await runHook(service.port, 'PostToolUse', 'Edit', { file_path: 'a.js', old_string: 'x', new_string: 'y' });
  await service.close();
  service = await startService({ folder, port: 0 });
  try {
    const status = await (await fetch(`http://127.0.0.1:${service.port}/status`)).json();
    assert.equal(status.entries, 2);
    const r = await runHook(service.port, 'PostToolUse', 'Write', { file_path: 'b.js', content: 'z' });
    assert.equal(r.code, 0, r.err);
    assert.equal((await (await fetch(`http://127.0.0.1:${service.port}/status`)).json()).entries, 3);
    const sealer = await loadRecorderKeys(folder);
    assert.equal(sealer.keys.length, 3);
    assert.equal(sealer.keys[2].alg, 'SLH-DSA-SHA2-256s');
  } finally {
    await service.close();
  }
});

test('with no recorder running, a call is refused before and reported after', async () => {
  const free = await startService({ folder: (await world()).folder, port: 0 });
  const port = free.port;
  await free.close();
  const before = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' });
  assert.equal(before.code, 0);
  assert.equal(before.decision.permissionDecision, 'deny');
  assert.match(before.decision.permissionDecisionReason, /not running/);
  const after = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' });
  assert.equal(after.code, 2);
  assert.match(after.err, /was not written/);
});

test('the service refuses a slip that names other keys than the folder\'s', async () => {
  const { folder } = await world();
  const other = mkdtempSync(join(tmpdir(), 'provared-cc-'));
  await makeAgentKeys(other);
  writeFileSync(join(other, 'slip.json'), readFileSync(join(folder, 'slip.json')));
  await assert.rejects(startService({ folder: other, port: 0 }), /other keys/);
});
