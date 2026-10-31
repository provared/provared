// The Claude Code plugin: its manifest, its hooks file and the marketplace
// file at the top of the repository, as Claude Code's plugin documentation
// says it reads them (read on 31 October 2026); its hooks, which must do
// what the hooks "init" writes do; and what it says and refuses where
// nothing is set up yet, or where the recorder's hooks are in force twice.
//
// Imported with import(), after local-library.mjs (see that file).

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

const { hookSettings, startService, writeHooks } = await import('../recorder.mjs');
const { freePort, here, runHook, stopService, tempFolder, world } = await import('./world.mjs');
const { recorderHooksInSettings, removeInitHooks } = await import('../settings-hooks.mjs');

const pluginRoot = resolve(here, '..');
const repository = resolve(pluginRoot, '..', '..');
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const manifest = readJson(join(pluginRoot, '.claude-plugin', 'plugin.json'));
const hooksFile = readJson(join(pluginRoot, 'hooks', 'hooks.json'));
const marketplace = readJson(join(repository, '.claude-plugin', 'marketplace.json'));
const pkg = readJson(join(pluginRoot, 'package.json'));
// eslint-disable-next-line no-template-curly-in-string -- Claude Code's own variable, written as it is in the hooks file.
const ROOT = '${CLAUDE_PLUGIN_ROOT}';

// The top-level keys of plugin.json that Claude Code reads (the manifest reference's "Fields" table).
const MANIFEST_KEYS = ['$schema', 'name', 'displayName', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'metadata', 'icon', 'documentationUrl', 'supportUrl', 'privacyPolicyUrl', 'termsOfServiceUrl', 'defaultEnabled', 'dependencies', 'settings', 'userConfig', 'types', 'channels', 'skills', 'commands', 'agents', 'hooks', 'mcpServers', 'lspServers', 'outputStyles', 'workflows', 'experimental'];
// A name Claude Code refuses, or warns about, as passing for one of Anthropic's own.
const passesForAnthropic = (name) => /^cc-plugin-/i.test(name) || name.toLowerCase().split(/[^a-z]+/).some((word) => ['claude', 'anthropic', 'anthropics'].includes(word));
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

// Surroundings in which the hook runs as the plugin's: Claude Code names
// the plugin's folder (CLAUDE_PLUGIN_ROOT) and the project's, and the
// person's own settings are in a folder of the test's own.
function asPlugin(folder, project, claudeHome = tempFolder('provared-claude-home-')) {
  return { CLAUDE_PLUGIN_ROOT: pluginRoot, CLAUDE_PROJECT_DIR: project, CLAUDE_CONFIG_DIR: claudeHome, PROVARED_CLAUDE_CODE_DIR: folder };
}

// The hook command of an event in the plugin's hooks file, with the plugin's folder put in, as Claude Code puts it in.
const pluginArgs = (event) => hooksFile.hooks[event][0].hooks[0].args.map((a) => a.replaceAll(ROOT, pluginRoot));

test('the manifest is as Claude Code reads it, under a name that does not pass for Anthropic\'s own', () => {
  assert.deepEqual(Object.keys(manifest).filter((k) => !MANIFEST_KEYS.includes(k)), [], 'no field Claude Code would strip');
  assert.ok(manifest.name.split('-').every((part) => /^[a-z0-9]+$/.test(part)), 'kebab-case');
  assert.equal(passesForAnthropic(manifest.name), false);
  assert.equal(manifest.version, pkg.version, 'the plugin and the npm package are one version');
  assert.equal(typeof manifest.description, 'string');
  assert.equal(typeof manifest.author?.name, 'string');
  assert.doesNotThrow(() => new URL(manifest.homepage), 'Claude Code refuses a plugin whose homepage is not a URL');
  assert.equal(manifest.license, pkg.license);
  assert.equal(manifest.hooks, undefined, 'the hooks are in their default place, hooks/hooks.json');
  assert.ok(existsSync(join(pluginRoot, 'hooks', 'hooks.json')));
  assert.ok(!existsSync(join(pluginRoot, 'CLAUDE.md')), 'a CLAUDE.md at a plugin\'s root is not loaded, and the validator warns of it');
  assert.ok(!existsSync(join(pluginRoot, 'bin')), 'a bin folder would put files on the Bash tool\'s path, and keeps the plugin out of claude.ai');
});

test('the hooks file holds the hooks init writes, by the plugin\'s own paths, and each names a file that is there', () => {
  assert.deepEqual(Object.keys(hooksFile), ['hooks'], 'a hooks file wraps its events in "hooks"');
  const init = hookSettings({ hook: `${ROOT}/hook.mjs`, recorder: `${ROOT}/recorder.mjs` });
  assert.deepEqual(Object.keys(hooksFile.hooks).sort(), Object.keys(init).sort(), 'the same events as init');
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    assert.deepEqual(hooksFile.hooks[event], init[event], `${event}: what init writes, every tool, onFailure "block"`);
  }
  // The start of a session: as init's, but "session-start", which also says what stands in the way.
  const start = hooksFile.hooks.SessionStart[0].hooks[0];
  const initStart = init.SessionStart[0].hooks[0];
  assert.deepEqual({ ...start, args: start.args.slice(0, -1) }, { ...initStart, args: initStart.args.slice(0, -1) });
  assert.equal(start.args.at(-1), 'session-start');
  assert.equal(initStart.args.at(-1), 'ensure');
  for (const groups of Object.values(hooksFile.hooks)) {
    for (const h of groups.flatMap((g) => g.hooks)) {
      assert.equal(h.type, 'command');
      assert.equal(h.command, 'node', 'exec form: node is run directly, each argument as written');
      assert.ok(Array.isArray(h.args));
      const paths = h.args.filter((a) => a.includes(ROOT));
      assert.equal(paths.length, 1);
      assert.ok(paths[0].startsWith(`${ROOT}/`));
      assert.doesNotMatch(paths[0], /\.\.|\\/, 'no path out of the plugin, and forward slashes only');
      assert.ok(existsSync(join(pluginRoot, paths[0].slice(ROOT.length + 1))), `${paths[0]} is in the plugin`);
      assert.ok(h.timeout <= 30 && h.timeout > 25, 'longer than the hook\'s own wait for the recorder (25 seconds)');
    }
  }
});

test('the marketplace file at the top of the repository lists the plugin by a path inside it', () => {
  assert.match(marketplace.name, ID);
  assert.equal(passesForAnthropic(marketplace.name), false);
  assert.ok(!['npm', 'pip', 'uv', 'cargo', 'github', 'gh', 'inline', 'builtin', 'skills-dir', 'synced'].includes(marketplace.name.toLowerCase()), 'not a reserved name');
  assert.equal(typeof marketplace.owner?.name, 'string');
  assert.equal(marketplace.plugins.length, 1);
  const [entry] = marketplace.plugins;
  assert.equal(entry.name, manifest.name, 'installed by the name its components are known by');
  assert.match(entry.source, /^\.\/[^\\]*$/);
  assert.doesNotMatch(entry.source, /\.\./);
  assert.equal(resolve(repository, entry.source), pluginRoot);
  assert.equal(entry.version, undefined, 'the version is the manifest\'s alone');
  assert.equal(entry.hooks, undefined, 'the hooks are the plugin\'s own');
});

test('the lockfile lets Claude Code install the library into the plugin\'s copy, and the npm package holds every file the hook loads', () => {
  const lock = readJson(join(pluginRoot, 'package-lock.json'));
  assert.ok([2, 3].includes(lock.lockfileVersion), 'a lockfile npm 7 or later writes');
  assert.deepEqual(lock.packages[''].dependencies, pkg.dependencies, 'the same dependencies as package.json, or the install is skipped');
  assert.equal(pkg.overrides, undefined, 'no npm overrides, or the install is skipped');
  assert.equal(pkg.scripts?.postinstall ?? pkg.scripts?.install ?? pkg.scripts?.preinstall, undefined);
  for (const [path, entry] of Object.entries(lock.packages).filter(([p]) => p !== '')) {
    assert.match(entry.version, /^\d+\.\d+\.\d+$/, `${path} is pinned to one version`);
    assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//, `${path} comes from the registry, over https`);
    assert.match(entry.integrity, /^sha512-/);
  }
  const library = lock.packages['node_modules/provared'];
  const [, major, minor] = pkg.dependencies.provared.match(/^\^(\d+)\.(\d+)\.\d+$/);
  assert.equal(library.version.split('.').slice(0, 2).join('.'), `${major}.${minor}`, 'the version pinned is within the range package.json asks for');
  // Every file of this folder that the hook and the recorder load is in the npm package as well.
  const local = new Set();
  for (const file of readdirSync(pluginRoot).filter((f) => f.endsWith('.mjs'))) {
    for (const m of readFileSync(join(pluginRoot, file), 'utf8').matchAll(/(?:from |import\()'\.\/([^']+)'/g)) local.add(m[1]);
  }
  for (const file of local) assert.ok(pkg.files.includes(file), `${file} is in the npm package`);
});

test('as the plugin, the hooks ask before a call and record it after, as init\'s do', async () => {
  const { folder } = await world([]);
  const project = tempFolder('provared-project-');
  const service = await startService({ folder, port: 0 });
  try {
    const env = asPlugin(folder, project);
    const before = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { file: pluginArgs('PreToolUse')[1], env });
    assert.equal(before.code, 0, before.err);
    assert.equal(before.out, '', 'allowed');
    const after = await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' }, { file: pluginArgs('PostToolUse')[1], env });
    assert.equal(after.code, 0, after.err);
    const failed = await runHook(service.port, 'PostToolUseFailure', 'Edit', { file_path: 'a.js' }, { file: pluginArgs('PostToolUseFailure')[1], env, more: { error: 'no such file' } });
    assert.equal(failed.code, 0, failed.err);
    const refused = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'rm -rf build' }, { file: pluginArgs('PreToolUse')[1], env });
    assert.equal(refused.decision.permissionDecision, 'deny', 'outside the permission: refused, as by init\'s hook');
    assert.equal((await (await fetch(`http://127.0.0.1:${service.port}/status`)).json()).entries, 3, 'the slip and two stubs');
  } finally {
    await service.close();
  }
});

test('with the recorder\'s hooks also in a settings file, the plugin refuses each call and says how to take one out', async () => {
  const { folder } = await world([]);
  const project = tempFolder('provared-project-');
  const claudeHome = tempFolder('provared-claude-home-');
  const service = await startService({ folder, port: 0 });
  try {
    const env = asPlugin(folder, project, claudeHome);
    writeHooks(project);
    const doubled = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { file: pluginArgs('PreToolUse')[1], env });
    assert.equal(doubled.decision.permissionDecision, 'deny');
    assert.match(doubled.decision.permissionDecisionReason, /in force twice/);
    assert.match(doubled.decision.permissionDecisionReason, /settings\.local\.json/);
    assert.match(doubled.decision.permissionDecisionReason, /remove-hooks/);
    assert.match(doubled.decision.permissionDecisionReason, /claude plugin disable provared-recorder@provared/);
    // The hook of the settings file, which Claude Code runs without naming this plugin's folder, is not refused: with no plugin folder, or another plugin's.
    for (const root of ['', tempFolder('provared-another-plugin-')]) {
      const settingsHook = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { env: { ...env, CLAUDE_PLUGIN_ROOT: root } });
      assert.equal(settingsHook.out, '', root || 'no plugin folder');
    }
    // After a call is taken, the plugin still records it: a stub twice is a fault the record shows, a missing one is not.
    const after = await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm test' }, { file: pluginArgs('PostToolUse')[1], env });
    assert.equal(after.code, 0, after.err);
    // In the person's own settings, by hand, with the project's folder written as Claude Code writes it: also found.
    const home = join(claudeHome, 'settings.json');
    writeFileSync(home, JSON.stringify({ hooks: { PostToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `node "${pluginRoot}/hook.mjs" && echo done` }] }] } }));
    assert.deepEqual(recorderHooksInSettings(project, [home]).map((f) => f.event), ['PostToolUse']);
    // eslint-disable-next-line no-template-curly-in-string -- Claude Code's own variable, as settings.example.json writes it.
    writeFileSync(home, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'node', args: ['${CLAUDE_PROJECT_DIR}/integrations/claude-code/hook.mjs'] }] }] } }));
    assert.equal(recorderHooksInSettings(repository, [home]).length, 1, 'the form of settings.example.json');
    assert.equal(recorderHooksInSettings(project, [home]).length, 0, 'where the project holds no recorder there');
    // Another file named hook.mjs, with no recorder beside it, is not the recorder's.
    const lone = tempFolder('provared-lone-');
    writeFileSync(join(lone, 'hook.mjs'), '');
    writeFileSync(home, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'node', args: [join(lone, 'hook.mjs')] }] }] } }));
    assert.equal(recorderHooksInSettings(project, [home]).length, 0);
  } finally {
    await service.close();
  }
});

test('"remove-hooks" takes out the hooks init wrote, from any copy, and nothing else', () => {
  const project = tempFolder('provared-project-');
  const settings = join(project, '.claude', 'settings.local.json');
  mkdirSync(join(project, '.claude'), { recursive: true });
  const mine = { type: 'command', command: 'echo mine' };
  // A hook of the person's own that runs the recorder's hook and something more stays, as init leaves it.
  const wrapped = { type: 'command', command: `node "${pluginRoot}/hook.mjs" && echo more` };
  writeFileSync(settings, '﻿' + JSON.stringify({ permissions: { allow: ['Read'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [mine] }, { matcher: 'Edit', hooks: [wrapped] }] } }));
  writeHooks(project);
  // An older copy's hook, written as one command line.
  const older = tempFolder('provared-older-copy-');
  for (const f of ['hook.mjs', 'recorder.mjs', 'actions.mjs']) writeFileSync(join(older, f), '');
  const read = () => JSON.parse(readFileSync(settings, 'utf8').replace(/^﻿/, ''));
  const s = read();
  s.hooks.PostToolUse.push({ matcher: '*', hooks: [{ type: 'command', command: `node ${join(older, 'hook.mjs')}` }] });
  writeFileSync(settings, '﻿' + JSON.stringify(s));
  const written = [];
  const removed = removeInitHooks(project, (path, text) => {
    written.push(path);
    writeFileSync(path, text);
  });
  assert.equal(removed.removed, 5, 'four of this copy\'s, one of the older copy\'s');
  assert.deepEqual(read(), { permissions: { allow: ['Read'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [mine] }, { matcher: 'Edit', hooks: [wrapped] }] } });
  assert.ok(readFileSync(settings, 'utf8').startsWith('﻿'), 'the byte-order mark is kept');
  // Nothing left to take out: the file is not written again.
  assert.equal(removeInitHooks(project, () => assert.fail('written')).removed, 0);
  assert.equal(written.length, 1);
});

test('the start of a session, as the plugin: where nothing is signed it says what the person must do, and where all is well it says nothing', async () => {
  const folder = join(tempFolder(), 'claude-code');
  const project = tempFolder('provared-project-');
  const port = await freePort();
  const env = asPlugin(folder, project);
  // The command of the hooks file, as Claude Code runs it.
  const startArgs = pluginArgs('SessionStart');
  assert.equal(startArgs.at(-1), 'session-start');
  const { spawnSync } = await import('node:child_process');
  const run = () => spawnSync(process.execPath, startArgs, { cwd: project, encoding: 'utf8', env: { ...process.env, ...env, PROVARED_CLAUDE_CODE_PORT: String(port) } });
  try {
    let r = run();
    assert.equal(r.status, 0, r.stderr);
    const said = JSON.parse(r.stdout);
    assert.equal(said.hookSpecificOutput.hookEventName, 'SessionStart');
    assert.equal(said.systemMessage, said.hookSpecificOutput.additionalContext, 'told to the person and to Claude alike');
    assert.match(said.systemMessage, /no permission has been signed/);
    assert.match(said.systemMessage, /recorder\.mjs init/);
    assert.match(said.systemMessage, /https:\/\/sign\.prova\.red\//);
    assert.match(said.systemMessage, /recorder\.mjs use <the saved file>/);
    assert.match(said.systemMessage, /Nothing signs for you/);
    assert.ok(!existsSync(join(folder, 'agent-keys.jwk')), 'it makes no keys: init does, at the person\'s word');
    // The hook before a call says the same, in short, to Claude.
    const before = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' }, { file: pluginArgs('PreToolUse')[1], env });
    assert.equal(before.decision.permissionDecision, 'deny');
    assert.match(before.decision.permissionDecisionReason, /no permission has been signed for this agent yet/);
    assert.match(before.decision.permissionDecisionReason, /init/);
    assert.match(before.decision.permissionDecisionReason, /sign\.prova\.red/);
    // Set up: a permission in place, and the recorder started by the start of the session, which then says nothing.
    const w = await world([]);
    cpSync(w.folder, folder, { recursive: true });
    r = run();
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, '', 'nothing to say where all is well');
    const status = await (await fetch(`http://127.0.0.1:${port}/status`)).json();
    assert.equal(status.entries, 1, 'started, with the permission');
  } finally {
    await stopService(port);
  }
});

test('init, with --no-hooks or from Claude Code\'s plugin cache, writes no hooks; with anything else after it, it does nothing', async () => {
  const { spawnSync } = await import('node:child_process');
  const project = tempFolder('provared-project-');
  const folder = join(tempFolder(), 'claude-code');
  const port = await freePort();
  const home = tempFolder('provared-claude-home-');
  const run = (script, args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', script, ...args], { cwd: project, encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port), CLAUDE_CONFIG_DIR: home } });
  let r = run(join(pluginRoot, 'recorder.mjs'), ['init', '--no-hook']);
  assert.equal(r.status, 2, 'a misspelt switch writes nothing');
  assert.ok(!existsSync(join(folder, 'agent-keys.jwk')));
  r = run(join(pluginRoot, 'recorder.mjs'), ['init', '--no-hooks']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /No hooks were written \(--no-hooks\)/);
  assert.match(r.stdout, /https:\/\/sign\.prova\.red\/#permission=/);
  assert.ok(!existsSync(join(project, '.claude')));
  // A copy of the plugin as Claude Code installs it, in its cache.
  const cached = join(home, 'plugins', 'cache', 'provared', manifest.name, manifest.version);
  cpSync(pluginRoot, cached, { recursive: true, filter: (p) => !p.includes('node_modules') && !p.includes(`${join(pluginRoot, 'test')}`) });
  r = run(join(cached, 'recorder.mjs'), ['init']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /No hooks were written: this copy of the recorder is the Claude Code plugin's/);
  assert.ok(!existsSync(join(project, '.claude')));
  // init from another copy, with the plugin installed: the hooks are written, and the person is warned.
  mkdirSync(join(home, 'plugins'), { recursive: true });
  writeFileSync(join(home, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { [`${manifest.name}@provared`]: [{ scope: 'user', installPath: cached }] } }));
  r = run(join(pluginRoot, 'recorder.mjs'), ['init']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /The hooks are in /);
  assert.match(r.stdout, /Warning: the Claude Code plugin provared-recorder is installed too/);
  assert.match(r.stdout, /remove-hooks/);
  // And remove-hooks takes them out again.
  r = run(join(pluginRoot, 'recorder.mjs'), ['remove-hooks']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Took 4 of the recorder's hooks out of /);
  assert.deepEqual(JSON.parse(readFileSync(join(project, '.claude', 'settings.local.json'), 'utf8')), { hooks: {} });
  r = run(join(pluginRoot, 'recorder.mjs'), ['remove-hooks']);
  assert.match(r.stdout, /holds none of the hooks init writes/);
});
