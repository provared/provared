// Setting the recorder up as a stranger would: "init" makes the keys,
// writes the hooks beside a project's own and prints a link to the signing
// page; the person signs; "use" puts the slip in place and starts the
// service; Claude Code's calls are recorded; "check" gives the checker's
// answer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';


const { assembleSlip, formatTime, fromBase64url, prepareSlip, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { hookSettings, loadAgentKeys, signingLink, startingPermission, writeHooks } = await import('../recorder.mjs');
const { freePort, recorderFile, runCommand, runHook, status, stopService, tempFolder } = await import('./world.mjs');

const slashes = (path) => path.split('\\').join('/');

// The signing page reads the starting permission as the page's script does:
// the "permission" part of the address's fragment, base64url of JSON, laid
// over the page's own starting point, whose times are set when it opens.
function fromLink(link) {
  const { hash } = new URL(link);
  const given = new URLSearchParams(hash.slice(1)).get('permission');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromBase64url(given)));
}

test('the hooks are added beside what a project has, never twice, and nothing else is taken out', () => {
  const project = tempFolder('provared-project-');
  mkdirSync(join(project, '.claude'));
  const path = join(project, '.claude', 'settings.local.json');
  const theirs = { type: 'command', command: 'echo', args: ['hello'] };
  const older = { type: 'command', command: 'node', args: ['/somewhere/provared/integrations/claude-code/hook.mjs'] };
  writeFileSync(path, JSON.stringify({ permissions: { allow: ['Bash(npm test)'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [theirs] }], PostToolUse: [{ matcher: 'Read', hooks: [older] }] } }));
  const first = writeHooks(project);
  assert.equal(first.added, 4);
  assert.equal(first.present, 0);
  assert.equal(first.others.length, 1, 'an older Provared hook is reported');
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  assert.deepEqual(settings.permissions, { allow: ['Bash(npm test)'] });
  assert.deepEqual(settings.hooks.PreToolUse[0], { matcher: 'Bash', hooks: [theirs] }, 'their hook is kept, first');
  assert.deepEqual(settings.hooks.PostToolUse[0], { matcher: 'Read', hooks: [older] }, 'the older hook is reported, not taken out');
  const ours = hookSettings();
  assert.deepEqual(settings.hooks.PreToolUse[1], ours.PreToolUse[0]);
  assert.deepEqual(settings.hooks.SessionStart, ours.SessionStart);
  assert.deepEqual(settings.hooks.PostToolUseFailure, ours.PostToolUseFailure);
  // Every tool, before, after, and after a failure; a hook that cannot run refuses the call.
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    assert.equal(ours[event][0].matcher, '*', event);
    assert.equal(ours[event][0].hooks[0].onFailure, 'block', event);
    assert.deepEqual(ours[event][0].hooks[0].args, ['--disable-warning=ExperimentalWarning', slashes(join(recorderFile, '..', 'hook.mjs'))]);
  }
  assert.equal(ours.SessionStart[0].hooks[0].onFailure, undefined, 'a session still starts when the recorder does not');
  assert.deepEqual(ours.SessionStart[0].hooks[0].args, ['--disable-warning=ExperimentalWarning', slashes(recorderFile), 'ensure']);
  // Again: nothing is added, and the file is not written.
  const text = readFileSync(path, 'utf8');
  const second = writeHooks(project);
  assert.equal(second.added + second.replaced, 0);
  assert.equal(second.present, 4);
  assert.equal(readFileSync(path, 'utf8'), text);
});

test('an earlier entry of the same hook, with a narrower matcher, is brought up to date; what shares its group stays', () => {
  const project = tempFolder('provared-project-');
  mkdirSync(join(project, '.claude'));
  const path = join(project, '.claude', 'settings.local.json');
  const ours = hookSettings();
  const theirs = { type: 'command', command: 'echo', args: ['hello'] };
  const earlier = { type: 'command', command: 'node', args: ours.PreToolUse[0].hooks[0].args, timeout: 30 };
  // Shaped as the settings this recorder was first set up with: the
  // recorder started beside another program's hook, and a list of tools.
  const uploader = { type: 'command', command: 'node', args: ['--disable-warning=ExperimentalWarning', 'D:/elsewhere/upload.mjs', '--ensure'], timeout: 30 };
  const start = ours.SessionStart[0].hooks[0];
  writeFileSync(path, JSON.stringify({ hooks: {
    SessionStart: [{ hooks: [start, uploader] }],
    PreToolUse: [{ matcher: 'Read|Bash', hooks: [theirs, earlier] }],
    PostToolUse: [{ matcher: 'Read|Bash', hooks: [earlier] }],
  } }));
  const written = writeHooks(project);
  assert.equal(written.present, 1, 'the start is there already, beside the other program');
  assert.equal(written.replaced, 2);
  assert.equal(written.added, 1, 'PostToolUseFailure');
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  assert.deepEqual(settings.hooks.SessionStart, [{ hooks: [start, uploader] }], 'left exactly as it was');
  assert.deepEqual(settings.hooks.PreToolUse, [{ matcher: 'Read|Bash', hooks: [theirs] }, ours.PreToolUse[0]]);
  assert.deepEqual(settings.hooks.PostToolUse, [ours.PostToolUse[0]], 'a group left empty is taken out');
  assert.deepEqual(settings.hooks.PostToolUseFailure, ours.PostToolUseFailure);
  assert.deepEqual(written.others, []);
});

test('a settings file that is not JSON, or not as Claude Code writes it, is left as it is', () => {
  const project = tempFolder('provared-project-');
  mkdirSync(join(project, '.claude'));
  const path = join(project, '.claude', 'settings.local.json');
  for (const text of ['{ "hooks": ', '[]', '{"hooks": []}', '{"hooks": {"PreToolUse": {}}}']) {
    writeFileSync(path, text);
    assert.throws(() => writeHooks(project), /left as it is/);
    assert.equal(readFileSync(path, 'utf8'), text);
  }
});

test('the signing link carries the starting permission, with the agent\'s public keys, in its fragment', async () => {
  const folder = tempFolder();
  const { makeAgentKeys } = await import('../recorder.mjs');
  const agent = await makeAgentKeys(folder);
  const link = signingLink(startingPermission(agent.keys));
  assert.ok(link.startsWith('https://prova.red/sign/#permission='));
  assert.match(link.split('#permission=')[1], /^[A-Za-z0-9_-]+$/, 'base64url only, so nothing in it needs escaping');
  const permission = fromLink(link);
  assert.deepEqual(permission, startingPermission(agent.keys));
  assert.deepEqual(permission.agent.keys, agent.keys);
  assert.equal(permission.issuer, undefined, 'the person and their passkey are the issuer');
  assert.equal(permission.validFrom, undefined, 'the page sets the times when it is opened');
  // Nothing private: the public keys only.
  assert.doesNotMatch(link, /"d"|"priv"/);
  assert.doesNotMatch(JSON.stringify(permission), /"d":|"priv":/);
});

test('from nothing to a recorded, checked session: init, sign, use, the calls, seal, check', async () => {
  const folder = join(tempFolder(), 'claude-code'); // the folder does not exist yet
  const project = tempFolder('provared-project-');
  const port = await freePort();
  try {
    // 1. init, in the project's folder
    const setUp = await runCommand(['init'], { folder, port, cwd: project });
    assert.equal(setUp.code, 0, setUp.err);
    assert.match(setUp.out, /The hooks are in /);
    const settings = JSON.parse(readFileSync(join(project, '.claude', 'settings.local.json'), 'utf8'));
    assert.deepEqual(Object.keys(settings.hooks).sort(), ['PostToolUse', 'PostToolUseFailure', 'PreToolUse', 'SessionStart']);
    const link = setUp.out.split('\n').map((l) => l.trim()).find((l) => l.startsWith('https://prova.red/sign/#permission='));
    assert.ok(link, setUp.out);
    // 2. The person signs on the page: the page lays the fragment over its own starting point, with the times it sets.
    const agent = await loadAgentKeys(folder);
    const fields = { ...fromLink(link), validFrom: formatTime(Date.now() - 60000), validUntil: formatTime(Date.now() + 7 * 86400000) };
    assert.deepEqual(fields.agent.keys, agent.keys);
    const passkey = await developmentPasskey();
    const prepared = await prepareSlip({ ...fields, issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin } });
    const saved = join(tempFolder('provared-downloads-'), 'slip.json');
    writeFileSync(saved, JSON.stringify(assembleSlip(prepared, await passkey.sign(prepared.challenge))));
    // 3. use
    const use = await runCommand(['use', saved], { folder, port, cwd: project });
    assert.equal(use.code, 0, use.err);
    assert.match(use.out, /The recorder is running/);
    // 4. Claude Code's calls, through the hook.
    let r = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' });
    assert.equal(r.out, '', 'allowed');
    r = await runHook(port, 'PostToolUse', 'Bash', { command: 'npm test' });
    assert.equal(r.code, 0, r.err);
    r = await runHook(port, 'PreToolUse', 'Bash', { command: 'rm -rf build' });
    assert.equal(r.decision.permissionDecision, 'deny', 'the starting permission forbids deleting');
    r = await runHook(port, 'PostToolUse', 'Edit', { file_path: 'a.js' });
    assert.equal(r.code, 0, r.err);
    // 5. seal and check: the checker's own answer, trusting the person's passkey and this recorder.
    const sealed = await runCommand(['seal'], { folder, port, cwd: project });
    assert.equal(sealed.code, 0, sealed.err);
    // Without --issuer: the passkeys the book names are shown, as read from the book, and none is taken as named.
    const mine = await thumbprint(passkey.key);
    const unnamed = await runCommand(['check'], { folder, port, cwd: project });
    assert.equal(unnamed.code, 1, `${unnamed.out}\n${unnamed.err}`);
    assert.match(unnamed.out, /Checked against keys you named\? +NO/);
    assert.doesNotMatch(unnamed.out, /Checked against keys you named\? +yes/);
    assert.match(unnamed.err, /read from the book itself, not named by you/);
    assert.match(unnamed.err, new RegExp(`passkey ${mine}`));
    assert.match(unnamed.err, /run again with --issuer/);
    // With the person's own passkey named: the checker's own answer, and code 0.
    const check = await runCommand(['check', '--issuer', mine], { folder, port, cwd: project });
    assert.equal(check.code, 0, `${check.out}\n${check.err}`);
    assert.match(check.out, /Did the agent stay within its slip\? +yes/);
    assert.match(check.out, /Checked against keys you named\? +yes/);
    assert.doesNotMatch(check.err, /not named by you/);
    // Another passkey named: the book's permission is not from it, which is a problem in the record.
    const other = await thumbprint((await developmentPasskey()).key);
    const wrong = await runCommand(['check', '--issuer', other], { folder, port, cwd: project });
    assert.equal(wrong.code, 2, `${wrong.out}\n${wrong.err}`);
    const s = await status(port);
    assert.equal(s.entries, 4, 'the slip, two stubs and a seal');
    const json = await runCommand(['check', '--issuer', mine, '--json'], { folder, port, cwd: project });
    assert.equal(JSON.parse(json.out).summary.intact, true, 'the checker\'s options are handed on, and its answer alone is printed');
    // status and stop
    const st = await runCommand(['status'], { folder, port, cwd: project });
    assert.equal(JSON.parse(st.out).slip, s.slip);
    const stop = await runCommand(['stop'], { folder, port, cwd: project });
    assert.equal(stop.code, 0);
    r = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' });
    assert.match(r.decision.permissionDecisionReason, /not running/);
  } finally {
    await stopService(port);
  }
});

test('"ensure" with no permission in place says so at once and starts nothing', async () => {
  const folder = tempFolder();
  const port = await freePort();
  const started = Date.now();
  const r = await runCommand(['ensure'], { folder, port });
  assert.equal(r.code, 1);
  assert.match(r.err, /no signed permission yet/);
  assert.ok(Date.now() - started < 5000);
  const s = await runCommand(['status'], { folder, port });
  assert.match(s.out, /not running/);
});

test('an unknown command prints how to use it', async () => {
  const folder = tempFolder();
  const r = await runCommand(['frobnicate'], { folder, port: await freePort() });
  assert.equal(r.code, 2);
  assert.match(r.out, /Usage: node .*recorder\.mjs <command>/);
  assert.match(r.out, /renew <file>/);
});
