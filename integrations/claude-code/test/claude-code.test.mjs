// The recorder beside Claude Code: the hook run as Claude Code runs it,
// against the service on a free port, under a slip signed with the
// library's development stand-in for a passkey.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { NOT_RECORDED, actionFor, commandAction, simpleCommands } from '../actions.mjs';

const { checkBook } = await import('provared');
const { loadRecorderKeys, loadSlip, makeAgentKeys, saveBook, startService } = await import('../recorder.mjs');
const { here, recorderFile, runHook, tempFolder, world } = await import('./world.mjs');

test('tool calls are named from the shared list, by the hook', () => {
  assert.equal(actionFor('Read', { file_path: 'a' }), 'provared.code.read');
  assert.equal(actionFor('Edit', {}), 'provared.code.change');
  assert.equal(actionFor('WebFetch', {}), 'provared.web.read');
  assert.equal(actionFor('Agent', {}), 'provared.agent.instruct');
  assert.equal(actionFor('SendMessage', { to: 'helper' }), 'provared.agent.instruct');
  assert.equal(actionFor('Artifact', {}), 'provared.code.release');
  assert.equal(actionFor('Bash', { command: 'npm test' }), 'provared.code.run');
  assert.equal(actionFor('mcp__example__search', {}), 'provared.code.run');
  // A tool not known here is recorded, under the widest name, never let through.
  assert.equal(actionFor('SomeToolAddedNextYear', {}), 'provared.code.run');
  assert.equal(actionFor('', {}), 'provared.code.run');
  assert.equal(actionFor(undefined, undefined), 'provared.code.run');
  // Only the tools that talk to the person or the model alone are not recorded.
  for (const name of NOT_RECORDED) assert.equal(actionFor(name, {}), null, name);
  assert.deepEqual(NOT_RECORDED, ['AskUserQuestion', 'TodoWrite', 'TodoRead', 'ExitPlanMode', 'EnterPlanMode', 'Skill', 'ToolSearch', 'EndConversation']);
  assert.equal(actionFor('askuserquestion', {}), 'provared.code.run', 'names are compared exactly');
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

// Each row: a command, and the name the hook gives it. A deletion wins over
// a release; the program is known in any letter case, by any path, with
// options before its command.
const NAMED = [
  // deletions
  ['del notes.txt', 'delete'],
  ['DEL notes.txt', 'delete'],
  ['RM -r build', 'delete'],
  ['remove-item -Recurse build', 'delete'],
  ['REMOVE-ITEM build', 'delete'],
  ['ri build', 'delete'],
  ['erase notes.txt', 'delete'],
  ['rd /s /q build', 'delete'],
  ['/bin/rm -rf build', 'delete'],
  ['"rm" -rf build', 'delete'],
  ['C:\\tools\\rm.exe build', 'delete'],
  ['sudo rm -rf /var/x', 'delete'],
  ['FOO=1 rm x', 'delete'],
  ['echo x | xargs rm', 'delete'],
  ['find . -name "*.log" -delete', 'delete'],
  ['find . -exec rm {} +', 'delete'],
  ['Clear-Content notes.txt', 'delete'],
  ['npm unpublish provared@0.3.0', 'delete'],
  ['npm.cmd unpublish x --force', 'delete'],
  ['gh repo delete owner/repo --yes', 'delete'],
  ['gh release delete v1 --yes', 'delete'],
  ['git push --force origin main', 'delete'],
  ['git push -f origin main', 'delete'],
  ['git push --force-with-lease origin main', 'delete'],
  ['git push --force-with-lease=main:abc origin main', 'delete'],
  ['git push origin +main', 'delete'],
  ['git push origin :old-branch', 'delete'],
  ['git push origin --delete old-branch', 'delete'],
  ['git -C repo push --force', 'delete'],
  ['git -C repo reset --hard HEAD~3', 'delete'],
  ['git branch -D old', 'delete'],
  ['git tag -d v1', 'delete'],
  ['git clean -fdx', 'delete'],
  ['git checkout -- .', 'delete'],
  ['bash -c "rm -rf build"', 'delete'],
  ['cmd /c del notes.txt', 'delete'],
  ['powershell -NoProfile -Command "Remove-Item build"', 'delete'],
  ['git push origin main && rm -rf build', 'delete'],
  ['npm publish; git push --force', 'delete'],
  ['shred -u secrets.txt', 'delete'],
  ['git stash drop', 'delete'],
  ['git stash clear', 'delete'],
  // Forms the first version caught and a shell reading alone missed (the re-review of 13 October 2026).
  ['echo \\" ; rm -rf build ; echo \\"', 'delete'],
  ["echo \\' ; rm -rf build ; echo \\'", 'delete'],
  ['echo `" ; Remove-Item -Recurse build ; echo `"', 'delete'],
  ['echo ${#PATH}; rm -rf build', 'delete'],
  ['Write-Output hi <# note #>; Remove-Item -Recurse build', 'delete'],
  ['2>/dev/null rm -rf build', 'delete'],
  ['>log.txt rm -rf build', 'delete'],
  ['sudo -u root rm -rf /srv/data', 'delete'],
  ['env -u HOME rm -rf build', 'delete'],
  ['timeout -s KILL 10 rm -rf build', 'delete'],
  ['bash -lc "cd x && rm -rf build"', 'delete'],
  ['bash -ec "rm -rf build"', 'delete'],
  ['git rm -rf src', 'delete'],
  ['ssh host rm -rf /srv/data', 'delete'],
  ['docker exec web rm -rf /data', 'delete'],
  ['wsl rm -rf /mnt/c/x', 'delete'],
  ['busybox rm -rf build', 'delete'],
  ['find . -delete', 'delete'],
  ['git -C repo push origin +main', 'delete'],
  ['gh repo delete o/r --yes', 'delete'],
  ['echo \\" ; git push --force ; echo \\"', 'delete'],
  // Forms only the shell-like reading names, each rule of it in turn: an escaped quotation mark, a
  // redirection, a wrapper's option with a value, a PowerShell comment, ${#…}; and forms only the
  // reading from every known program's name finds.
  ['echo \\" ; bash -c "rm -rf x"', 'delete'],
  ['2>/dev/null bash -c "rm -rf x"', 'delete'],
  ['sudo -u root bash -c "rm -rf x"', 'delete'],
  ['Write-Output hi <# note #>; powershell -Command "ri x"', 'delete'],
  ['echo ${#PATH}; bash -c "rm -rf x"', 'delete'],
  ['ssh host shred -u secrets', 'delete'],
  // A command line run by eval, iex or Invoke-Expression, by find -exec through a shell, or by cmd /c written without a space.
  ['eval "rm -rf x"', 'delete'],
  ["iex 'rm -r x'", 'delete'],
  ["Invoke-Expression -Command 'Remove-Item x'", 'delete'],
  ["find . -name '*.log' -exec sh -c 'rm \"$1\"' _ {} \\;", 'delete'],
  ['cmd /c"del x"', 'delete'],
  // In PowerShell and cmd, \; is a backslash and a break: the line is read both ways.
  ['Write-Output \\; cmd /c "del /q build"', 'delete'],
  ['Write-Output \\; powershell -Command "rm -r build"', 'delete'],
  ['Write-Output \\; iex "rm -r build"', 'delete'],
  ["Write-Output \\; bash -c 'rm -rf build'", 'delete'],
  ['eval "git push origin main"', 'release'],
  ['find . -exec bash -c "git push" \\;', 'release'],
  // releases
  ['npx npm --otp=1 publish', 'release'],
  ['git push origin main', 'release'],
  ['git -C repo push', 'release'],
  ['git -c user.name=x push origin main', 'release'],
  ['git --git-dir=.git push', 'release'],
  ['Git push', 'release'],
  ['GIT push origin main', 'release'],
  ['GIT_DIR=x git push', 'release'],
  ['git push -u origin feature', 'release'],
  ['npm publish', 'release'],
  ['npm.cmd publish --access public', 'release'],
  ['npm --otp=123456 publish', 'release'],
  ['npm -w pkg publish', 'release'],
  ['NPM publish', 'release'],
  ['pnpm --filter x publish', 'release'],
  ['yarn npm publish', 'release'],
  ['twine upload dist/*', 'release'],
  ['gh pr merge 12', 'release'],
  ['gh pr create --fill', 'release'],
  ['gh release create v1', 'release'],
  ['docker push me/img', 'release'],
  ['python -m twine upload dist/*', 'release'],
  ['py -m twine upload dist/*', 'release'],
  ['npx npm publish', 'release'],
  ['echo \\" ; git push ; echo \\"', 'release'],
  // runs
  ['npm test', 'run'],
  ['echo "rm is a word"', 'run'],
  ['eval "echo hi"', 'run'],
  ["iex 'Get-ChildItem'", 'run'],
  ['find . -exec sh -c "cat x" \\;', 'run'],
  ['cmd /c"dir"', 'run'],
  ['git status && npm run build', 'run'],
  ['git restore --staged a.js', 'run'],
  ['git branch -v', 'run'],
  // The first version's patterns are kept, so these read as it read them: stricter than a shell would run them.
  ['echo rm # git push', 'delete'],
  ['git clean -n', 'delete'],
  ['git rm --cached a.js', 'delete'],
  ['grep -r "git push" docs', 'release'],
];

test('commands are named by what they do: deletions, releases and runs', () => {
  const name = { delete: 'provared.data.delete', release: 'provared.code.release', run: 'provared.code.run' };
  const wrong = NAMED.filter(([command, kind]) => commandAction(command) !== name[kind]).map(([command, kind]) => `${command} -> ${commandAction(command)}, not ${kind}`);
  assert.deepEqual(wrong, []);
  assert.equal(actionFor('PowerShell', { command: 'RM build' }), 'provared.data.delete');
  assert.equal(actionFor('PowerShell', { command: 'Remove-Item build' }), 'provared.data.delete');
  // A reading of the text can be got round, and is stated to be one: a name built in a variable reads as a run.
  assert.equal(commandAction('x=rm; $x -rf build'), 'provared.code.run');
  assert.deepEqual(simpleCommands('a "b c" \'d\' # e\nf; g | h'), [['a', 'b c', 'd'], ['f'], ['g'], ['h']]);
});

test('a long chain of find -exec is read in a time in step with its length, well within the hook\'s limit, and a deletion after it is found', () => {
  // Read part by part, each -exec up to the next: before, each part was read with all the parts after it, and 80 links took seconds.
  const command = `find . ${'-exec find . '.repeat(120)}; rm -rf x`;
  const started = performance.now();
  assert.equal(commandAction(command), 'provared.data.delete');
  const took = performance.now() - started;
  assert.ok(took < 1000, `took ${Math.round(took)} ms`);
  assert.equal(commandAction(`find . -exec find . -exec rm {} \\; \\;`), 'provared.data.delete');
  assert.equal(commandAction(`find . -exec cat {} \\; -exec sh -c 'rm "$1"' _ {} \\;`), 'provared.data.delete');
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
    assert.match(status.validUntil, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
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
  assert.match(before.decision.permissionDecisionReason, /recorder\.mjs" start/, 'it names the command that starts the recorder beside this hook');
  const after = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' });
  assert.equal(after.code, 2);
  assert.match(after.err, /was not written/);
});

test('the service refuses a slip that names other keys than the folder\'s', async () => {
  const { folder } = await world();
  const other = tempFolder();
  await makeAgentKeys(other);
  writeFileSync(join(other, 'slip.json'), readFileSync(join(folder, 'slip.json')));
  await assert.rejects(startService({ folder: other, port: 0 }), /other keys/);
});

// On Windows a file cannot be replaced while another program holds it open,
// and an uploader or a virus scanner reads the book often. A book only
// grows, so the recorder appends; where it must replace the file, it tries
// again until the other program lets go.
test('the book is saved while another program holds it open', async () => {
  const folder = tempFolder('provared-save-');
  const book = join(folder, 'book.jsonl');
  saveBook(folder, 'one\n');
  const fd = openSync(book, 'r');
  try {
    saveBook(folder, 'one\ntwo\n');
    assert.equal(readFileSync(book, 'utf8'), 'one\ntwo\n', 'appended while held open');
    saveBook(folder, 'one\ntwo\n');
    assert.equal(readFileSync(book, 'utf8'), 'one\ntwo\n', 'nothing to add');
  } finally { closeSync(fd); }
  // A file that does not match the book is replaced, once the holder lets
  // go. The test waits for what it checks, never for a fixed time, so that
  // a slow machine changes nothing: the other program holds the file until
  // it is told to let go, and the saving is done by a program of its own,
  // so that this one can watch it.
  const holder = spawn(process.execPath, ['-e', 'const fs=require("fs");const fd=fs.openSync(process.argv[1],"r");process.stdout.write("open");process.stdin.on("end",()=>fs.closeSync(fd));process.stdin.resume()', book], { stdio: ['pipe', 'pipe', 'ignore'] });
  await new Promise((r) => holder.stdout.once('data', r));
  const saver = spawn(process.execPath, ['--input-type=module', '-e', `const { saveBook } = await import(${JSON.stringify(pathToFileURL(recorderFile).href)}); saveBook(${JSON.stringify(folder)}, 'other\\n');`], { stdio: ['ignore', 'ignore', 'pipe'] });
  let err = '';
  saver.stderr.on('data', (d) => (err += d));
  const saved = new Promise((r) => saver.on('close', r));
  if (process.platform === 'win32') {
    // While the file is held, the saver waits: its new text stands beside the book, and the book is as it was.
    await until(() => existsSync(`${book}.tmp`));
    assert.equal(readFileSync(book, 'utf8'), 'one\ntwo\n', 'not replaced while another program holds it');
  }
  holder.stdin.end();
  assert.equal(await saved, 0, err);
  assert.equal(readFileSync(book, 'utf8'), 'other\n', 'replaced once the other program let go');
  assert.equal(existsSync(`${book}.tmp`), false);
  await new Promise((r) => (holder.exitCode !== null ? r() : holder.on('exit', r)));
});

// Wait until a condition holds, checking it every 10 thousandths of a second, for at most a minute.
async function until(condition) {
  const end = Date.now() + 60000;
  while (!condition()) {
    if (Date.now() > end) throw new Error('The condition did not come to hold within a minute.');
    await new Promise((r) => setTimeout(r, 10));
  }
}

test('a call that started and failed is recorded, with the tool named as failed and the fingerprint of the error', async () => {
  const { argumentsFingerprint, sha256, toBase64url, utf8 } = await import('provared');
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    const error = 'Exit code 1\nError: Cannot find module';
    const r = await runHook(service.port, 'PostToolUseFailure', 'Bash', { command: 'npm test' }, { more: { error, is_interrupt: false, duration_ms: 4187 } });
    assert.equal(r.code, 0, r.err);
    // A tool of an MCP server, which failed, and one that succeeded.
    assert.equal((await runHook(service.port, 'PostToolUseFailure', 'mcp__example__search', { q: 'x' }, { more: { error: 'timeout' } })).code, 0);
    assert.equal((await runHook(service.port, 'PostToolUse', 'mcp__example__search', { q: 'y' })).code, 0);
    const { issuerKey } = await loadSlip(folder);
    const result = await checkBook(readFileSync(join(folder, 'book.jsonl'), 'utf8'), { issuerKeys: [issuerKey] });
    assert.equal(result.summary.intact, true, JSON.stringify(result.entries.flatMap((e) => e.problems)));
    const stubs = result.entries.filter((e) => e.kind === 'stub').map((e) => e.content);
    assert.deepEqual(stubs.map((s) => s.action), ['provared.code.run', 'provared.code.run', 'provared.code.run']);
    assert.deepEqual(stubs[0].details, [
      { name: 'Bash (failed)', sha256: await argumentsFingerprint({ command: 'npm test' }) },
      { name: 'error', sha256: toBase64url(await sha256(utf8(error))) },
    ]);
    assert.equal(stubs[1].details[0].name, 'mcp__example__search (failed)');
    assert.deepEqual(stubs[2].details.map((d) => d.name), ['mcp__example__search']);
  } finally {
    await service.close();
  }
});

test('the hook fails closed: whatever goes wrong, a call is refused before and reported after', async () => {
  const { createServer } = await import('node:http');
  const { copyFileSync } = await import('node:fs');
  // Input that cannot be read: the event is not known, so exit code 2, which refuses a call not yet taken.
  let r = await runHook(1, null, null, null, { input: '{ not json' });
  assert.equal(r.code, 2);
  assert.match(r.err, /the hook beside Claude Code failed/);
  // The library cannot be loaded: a copy of the hook where "provared" cannot be found.
  const bare = tempFolder('provared-bare-');
  for (const name of ['hook.mjs', 'actions.mjs']) copyFileSync(join(here, '..', name), join(bare, name));
  const plain = { file: join(bare, 'hook.mjs'), env: { NODE_OPTIONS: '' } };
  r = await runHook(1, 'PreToolUse', 'Bash', { command: 'npm test' }, plain);
  assert.equal(r.code, 0, r.err);
  assert.equal(r.decision.permissionDecision, 'deny');
  assert.match(r.decision.permissionDecisionReason, /failed .*not taken/);
  r = await runHook(1, 'PostToolUse', 'Bash', { command: 'npm test' }, plain);
  assert.equal(r.code, 2);
  assert.match(r.err, /was taken and is not in the record/);
  r = await runHook(1, 'PreToolUse', 'AskUserQuestion', {}, plain);
  assert.equal(r.code, 0, 'a call that is not recorded does not need the library');
  assert.equal(r.out, '');
  // A service that answers, but not as the recorder does.
  for (const [status, body] of [[500, 'not json'], [200, '{}']]) {
    const odd = createServer((req, res) => { req.resume(); res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(body); });
    await new Promise((resolve) => odd.listen(0, '127.0.0.1', resolve));
    try {
      r = await runHook(odd.address().port, 'PreToolUse', 'Bash', { command: 'npm test' });
      assert.equal(r.code, 0, r.err);
      assert.equal(r.decision.permissionDecision, 'deny', body);
      assert.match(r.decision.permissionDecisionReason, /not taken/);
      r = await runHook(odd.address().port, 'PostToolUse', 'Bash', { command: 'npm test' });
      assert.equal(r.code, body === '{}' ? 0 : 2, 'a stub the service said it wrote is taken at its word; one it did not, is reported');
    } finally {
      await new Promise((resolve) => odd.close(resolve));
    }
  }
});
