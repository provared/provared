// The Claude Code plugin: its manifest, its hooks file and the marketplace
// file at the top of the repository, as Claude Code's plugin documentation
// says it reads them (read on 31 October 2026); its entry (plugin.mjs),
// which finds the library by an exact path and never in a folder above the
// plugin; its hooks, which must do what the hooks "init" writes do; and what
// it says and refuses where nothing is set up yet, where the library is
// missing, or where the recorder's hooks are in force twice.
//
// Imported with import(), after local-library.mjs (see that file).

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

const { hookSettings, replaceIfUnchanged, startService, writeHooks } = await import('../recorder.mjs');
const { freePort, here, runHook, stopService, tempFolder, world } = await import('./world.mjs');
const { lineWords, recorderHooksInSettings, removeInitHooks, samePath } = await import('../settings-hooks.mjs');
const { dataFolder, lockFingerprint } = await import('../plugin-library.mjs');

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

/**
 * A plugin data folder holding the library where the plugin installs it
 * (library-<fingerprint>/node_modules/provared): here a few small files that
 * stand for this repository's own library, as
 * tools/use-repository-library.mjs writes them, so that no test reaches npm.
 */
function dataWithLibrary() {
  const data = tempFolder('provared-plugin-data-');
  const target = join(data, `library-${lockFingerprint()}`, 'node_modules', 'provared');
  const library = readJson(join(repository, 'package.json'));
  const write = (file, text) => {
    mkdirSync(dirname(join(target, file)), { recursive: true });
    writeFileSync(join(target, file), text);
  };
  for (const entry of Object.values(library.exports)) {
    const file = typeof entry === 'string' ? entry : entry.default;
    if (file !== './package.json') write(file, `export * from '${pathToFileURL(join(repository, file)).href}';\n`);
  }
  write('bin/provared-check.mjs', `import '${pathToFileURL(join(repository, 'bin', 'provared-check.mjs')).href}';\n`);
  write('package.json', JSON.stringify({ name: 'provared', version: library.version, type: 'module', exports: library.exports }));
  return data;
}

// Surroundings in which the hook runs as the plugin's: Claude Code names
// the plugin's folder (CLAUDE_PLUGIN_ROOT), its data folder and the
// project's, and the person's own settings are in a folder of the test's own.
function asPlugin(folder, project, { claudeHome = tempFolder('provared-claude-home-'), data = dataWithLibrary() } = {}) {
  return { CLAUDE_PLUGIN_ROOT: pluginRoot, CLAUDE_PLUGIN_DATA: data, CLAUDE_PROJECT_DIR: project, CLAUDE_CONFIG_DIR: claudeHome, PROVARED_CLAUDE_CODE_DIR: folder };
}

// The command of an event in the plugin's hooks file, with the plugin's folder (or another copy's) put in, as Claude Code puts it in.
const pluginArgs = (event, root = pluginRoot) => hooksFile.hooks[event][0].hooks[0].args.map((a) => a.replaceAll(ROOT, root));

/** Run the plugin's entry as Claude Code, or the person, runs it, with JSON on standard input. */
function runPlugin(args, { env = {}, input = '', cwd } = {}) {
  return new Promise((done) => {
    const child = spawn(process.execPath, args, { cwd, env: { ...process.env, ...env } });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => done({ code, out: out.trim(), err: err.trim(), decision: (() => { try { return JSON.parse(out).hookSpecificOutput; } catch { return null; } })() }));
    child.stdin.end(input);
  });
}
let calls = 0;
const callInput = (event, tool, toolInput, more = {}) => JSON.stringify({ session_id: 'test', hook_event_name: event, tool_name: tool, tool_input: toolInput, tool_use_id: `toolu_plugin_${++calls}`, ...more });
const hookAsPlugin = (port, event, tool, toolInput, env, more) => runPlugin(pluginArgs(event), { env: { ...env, PROVARED_CLAUDE_CODE_PORT: String(port) }, input: callInput(event, tool, toolInput, more) });

// npm, where a test lets the plugin try to install the library: from an empty cache and with no network, so that it fails at once.
const npmOffline = () => ({ npm_config_offline: 'true', npm_config_cache: tempFolder('provared-npm-cache-'), npm_config_update_notifier: 'false' });

/** A copy of the plugin as Claude Code installs it, in a plugin cache under "home", with nothing beside it. */
function cachedCopy(home) {
  const cached = join(home, 'plugins', 'cache', 'provared', manifest.name, manifest.version);
  const skip = [join(pluginRoot, 'test'), join(pluginRoot, 'node_modules')];
  cpSync(pluginRoot, cached, { recursive: true, filter: (p) => !skip.some((s) => p === s || p.startsWith(s + sep)) });
  return cached;
}

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

test('the hooks file holds the hooks init writes, run through the plugin\'s entry, and each names a file that is there', () => {
  assert.deepEqual(Object.keys(hooksFile), ['hooks'], 'a hooks file wraps its events in "hooks"');
  const init = hookSettings({ hook: `${ROOT}/hook.mjs`, recorder: `${ROOT}/recorder.mjs` });
  assert.deepEqual(Object.keys(hooksFile.hooks).sort(), Object.keys(init).sort(), 'the same events as init');
  // The same as init's, but through plugin.mjs, which finds the library first.
  const through = (h, words) => ({ ...h, args: [h.args[0], `${ROOT}/plugin.mjs`, ...words] });
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    const expected = init[event].map((g) => ({ ...g, hooks: g.hooks.map((h) => through(h, ['hook'])) }));
    assert.deepEqual(hooksFile.hooks[event], expected, `${event}: what init writes, every tool, onFailure "block"`);
  }
  const start = init.SessionStart.map((g) => ({ ...g, hooks: g.hooks.map((h) => through(h, ['session-start'])) }));
  assert.deepEqual(hooksFile.hooks.SessionStart, start);
  for (const groups of Object.values(hooksFile.hooks)) {
    for (const h of groups.flatMap((g) => g.hooks)) {
      assert.equal(h.type, 'command');
      assert.equal(h.command, 'node', 'exec form: node is run directly, each argument as written');
      const paths = h.args.filter((a) => a.includes(ROOT));
      assert.equal(paths.length, 1);
      assert.ok(paths[0].startsWith(`${ROOT}/`));
      assert.doesNotMatch(paths[0], /\.\.|\\/, 'no path out of the plugin, and forward slashes only');
      assert.ok(existsSync(join(pluginRoot, paths[0].slice(ROOT.length + 1))), `${paths[0]} is in the plugin`);
      assert.ok(h.timeout <= 30 && h.timeout > 27, 'longer than the 27 seconds the plugin keeps within');
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

test('the lockfile pins the library exactly, and the npm package holds every file its own files load', () => {
  const lock = readJson(join(pluginRoot, 'package-lock.json'));
  assert.ok([2, 3].includes(lock.lockfileVersion), 'a lockfile npm 7 or later writes');
  assert.deepEqual(lock.packages[''].dependencies, pkg.dependencies, 'the same dependencies as package.json, or npm ci refuses');
  assert.equal(pkg.overrides, undefined);
  assert.equal(pkg.scripts?.postinstall ?? pkg.scripts?.install ?? pkg.scripts?.preinstall, undefined);
  for (const [path, entry] of Object.entries(lock.packages).filter(([p]) => p !== '')) {
    assert.match(entry.version, /^\d+\.\d+\.\d+$/, `${path} is pinned to one version`);
    assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//, `${path} comes from the registry, over https`);
    assert.match(entry.integrity, /^sha512-/);
  }
  const library = lock.packages['node_modules/provared'];
  const [, major, minor] = pkg.dependencies.provared.match(/^\^(\d+)\.(\d+)\.\d+$/);
  assert.equal(library.version.split('.').slice(0, 2).join('.'), `${major}.${minor}`, 'the version pinned is within the range package.json asks for');
  // Every file of this folder that the npm package's own files load is in the npm package as well.
  for (const file of pkg.files.filter((f) => f.endsWith('.mjs'))) {
    for (const m of readFileSync(join(pluginRoot, file), 'utf8').matchAll(/(?:from |import\()'\.\/([^']+)'/g)) assert.ok(pkg.files.includes(m[1]), `${m[1]}, loaded by ${file}, is in the npm package`);
  }
});

test('the plugin\'s data folder is the one Claude Code names, for a copy in its cache, and none elsewhere', () => {
  const home = tempFolder('provared-claude-home-');
  const cached = cachedCopy(home);
  const saved = process.env.CLAUDE_PLUGIN_DATA;
  delete process.env.CLAUDE_PLUGIN_DATA;
  try {
    assert.equal(dataFolder(cached), join(home, 'plugins', 'data', 'provared-recorder-provared'));
    assert.equal(dataFolder(pluginRoot), null, 'a copy of the repository has none');
  } finally {
    if (saved !== undefined) process.env.CLAUDE_PLUGIN_DATA = saved;
  }
});

test('with no library for the plugin, it is never taken from a folder above, and each step says what to do', async () => {
  const home = tempFolder('provared-claude-home-');
  const cached = cachedCopy(home);
  // An unrelated copy of "provared" in a folder above the plugin, as in a person's home folder: never loaded.
  const decoy = join(home, 'node_modules', 'provared');
  mkdirSync(join(decoy, 'src'), { recursive: true });
  writeFileSync(join(decoy, 'package.json'), JSON.stringify({ name: 'provared', version: '9.9.9', type: 'module', exports: { '.': './src/index.js' } }));
  writeFileSync(join(decoy, 'src', 'index.js'), 'throw new Error("the copy above the plugin was loaded");\n');
  const project = tempFolder('provared-project-');
  const folder = join(tempFolder(), 'claude-code');
  const port = await freePort();
  const env = { CLAUDE_PLUGIN_ROOT: cached, CLAUDE_PROJECT_DIR: project, CLAUDE_CONFIG_DIR: home, PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port), ...npmOffline() };
  // Before a call: refused, and told plainly, with the one command that mends it. No install is tried then.
  const before = await runPlugin(pluginArgs('PreToolUse', cached), { env, input: callInput('PreToolUse', 'Bash', { command: 'npm test' }) });
  assert.equal(before.code, 0, before.err);
  assert.equal(before.decision.permissionDecision, 'deny');
  assert.match(before.decision.permissionDecisionReason, /library is not installed for the plugin/);
  assert.match(before.decision.permissionDecisionReason, /plugin\.mjs install-library/);
  assert.doesNotMatch(before.decision.permissionDecisionReason, /above the plugin was loaded/);
  assert.ok(!existsSync(join(home, 'plugins', 'data')), 'no install is tried before a call');
  // The start of a session tries to install it (here npm has no network), and says so.
  const start = await runPlugin(pluginArgs('SessionStart', cached), { env, cwd: project });
  assert.equal(start.code, 0, start.err);
  const said = JSON.parse(start.out);
  assert.equal(said.systemMessage, said.hookSpecificOutput.additionalContext);
  assert.match(said.systemMessage, /library is not installed for the plugin \(npm could not install/);
  assert.match(said.systemMessage, /every tool call is refused/);
  assert.match(said.systemMessage, /plugin\.mjs install-library/);
  // The person's own command: the same words, and code 1.
  const init = await runPlugin([join(cached, 'plugin.mjs'), 'init'], { env, cwd: project });
  assert.equal(init.code, 1);
  assert.match(init.err, /library is not installed for the plugin/);
  assert.ok(!existsSync(join(folder, 'agent-keys.jwk')));
  // With the library in the plugin's data folder, the same copy works.
  const data = dataWithLibrary();
  const ok = await runPlugin([join(cached, 'plugin.mjs'), 'install-library'], { env: { ...env, CLAUDE_PLUGIN_DATA: data } });
  assert.equal(ok.code, 0, ok.err);
  assert.match(ok.out, new RegExp(`installed for the plugin, in .*library-${lockFingerprint()}`));
  // And where Claude Code put the library beside the plugin, that copy is the one used.
  cpSync(join(data, `library-${lockFingerprint()}`, 'node_modules'), join(cached, 'node_modules'), { recursive: true });
  const beside = await runPlugin([join(cached, 'plugin.mjs'), 'install-library'], { env });
  assert.equal(beside.code, 0, beside.err);
  assert.ok(beside.out.includes(join(cached, 'node_modules', 'provared')), beside.out);
});

test('as the plugin, the hooks ask before a call and record it after, as init\'s do', async () => {
  const { folder } = await world([]);
  const project = tempFolder('provared-project-');
  const service = await startService({ folder, port: 0 });
  try {
    const env = asPlugin(folder, project);
    const before = await hookAsPlugin(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, env);
    assert.equal(before.code, 0, before.err);
    assert.equal(before.out, '', 'allowed');
    const after = await hookAsPlugin(service.port, 'PostToolUse', 'Bash', { command: 'npm test' }, env);
    assert.equal(after.code, 0, after.err);
    const failed = await hookAsPlugin(service.port, 'PostToolUseFailure', 'Edit', { file_path: 'a.js' }, env, { error: 'no such file' });
    assert.equal(failed.code, 0, failed.err);
    const refused = await hookAsPlugin(service.port, 'PreToolUse', 'Bash', { command: 'rm -rf build' }, env);
    assert.equal(refused.decision.permissionDecision, 'deny', 'outside the permission: refused, as by init\'s hook');
    assert.equal((await (await fetch(`http://127.0.0.1:${service.port}/status`)).json()).entries, 3, 'the slip and two stubs');
  } finally {
    await service.close();
  }
});

test('with the recorder\'s hooks also in a settings file (the project\'s local or shared one, or the person\'s own), the plugin refuses each call and says how to take one out', async () => {
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    for (const where of ['local', 'shared', 'own']) {
      const project = tempFolder('provared-project-');
      const claudeHome = tempFolder('provared-claude-home-');
      const env = asPlugin(folder, project, { claudeHome });
      if (where === 'local') writeHooks(project);
      const line = { hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: `node "${join(pluginRoot, 'hook.mjs')}"` }] }] } };
      if (where === 'shared') {
        mkdirSync(join(project, '.claude'), { recursive: true });
        writeFileSync(join(project, '.claude', 'settings.json'), JSON.stringify(line));
      }
      if (where === 'own') writeFileSync(join(claudeHome, 'settings.json'), JSON.stringify(line));
      const doubled = await hookAsPlugin(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, env);
      assert.equal(doubled.decision?.permissionDecision, 'deny', where);
      assert.match(doubled.decision.permissionDecisionReason, /in force twice/);
      assert.match(doubled.decision.permissionDecisionReason, /claude plugin disable provared-recorder@provared/);
      if (where === 'local') assert.match(doubled.decision.permissionDecisionReason, /plugin\.mjs remove-hooks/);
      else assert.match(doubled.decision.permissionDecisionReason, /by hand/);
      if (where !== 'local') continue;
      // The hook of the settings file, which Claude Code runs without naming this plugin's folder, is not refused: with no plugin folder, or another plugin's.
      for (const root of ['', tempFolder('provared-another-plugin-')]) {
        const settingsHook = await runHook(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, { env: { ...env, CLAUDE_PLUGIN_ROOT: root } });
        assert.equal(settingsHook.out, '', root || 'no plugin folder');
      }
      // After a call is taken, the plugin still records it: a stub twice is a fault the record shows, a missing one is not.
      const after = await hookAsPlugin(service.port, 'PostToolUse', 'Bash', { command: 'npm test' }, env);
      assert.equal(after.code, 0, after.err);
    }
  } finally {
    await service.close();
  }
});

test('the forms of a hook\'s command in which the recorder\'s hook is recognised', () => {
  const settings = join(tempFolder('provared-settings-'), 'settings.json');
  const found = (command, project = repository) => {
    writeFileSync(settings, JSON.stringify({ hooks: { PostToolUse: [{ hooks: [typeof command === 'string' ? { type: 'command', command } : command] }] } }));
    const { found: f, problem } = recorderHooksInSettings(project, [settings]);
    assert.equal(problem, null);
    return f.length;
  };
  const inRepo = 'integrations/claude-code/hook.mjs';
  assert.equal(found({ type: 'command', command: 'node', args: [`\${CLAUDE_PROJECT_DIR}/${inRepo}`] }), 1, 'the form of settings.example.json');
  assert.equal(found(`node "$CLAUDE_PROJECT_DIR"/${inRepo}`), 1, 'a quoted part joined to the rest of its word, as a shell joins it');
  assert.equal(found(`node '%CLAUDE_PROJECT_DIR%'/${inRepo} && echo done`), 1);
  assert.equal(found(`node "${join(pluginRoot, 'hook.mjs')}" && echo done`, tempFolder('provared-project-')), 1, 'an absolute path, with more after it');
  assert.equal(found(`node $CLAUDE_PROJECT_DIR/${inRepo}`, tempFolder('cc-empty-')), 0, 'where the project holds no recorder there');
  // The home folder, written as ~, $HOME or %USERPROFILE%.
  const home = tempFolder('provared-home-');
  const copy = join(home, 'tools', 'rec');
  mkdirSync(copy, { recursive: true });
  for (const f of ['hook.mjs', 'recorder.mjs', 'actions.mjs']) writeFileSync(join(copy, f), '');
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  try {
    // eslint-disable-next-line no-template-curly-in-string -- a shell's own way of writing the home folder.
    for (const word of ['~/tools/rec/hook.mjs', '$HOME/tools/rec/hook.mjs', '${HOME}/tools/rec/hook.mjs', '%USERPROFILE%\\tools\\rec\\hook.mjs', '$env:USERPROFILE\\tools\\rec\\hook.mjs']) {
      assert.equal(found(`node ${word}`), 1, word);
    }
    assert.equal(found('node $HOMEPATH/tools/rec/hook.mjs'), 0, '$HOMEPATH is not $HOME');
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  // A copy since deleted or moved, whose path names Provared: still the recorder's, since its hook still runs at every call.
  assert.equal(found('node /gone/provared/integrations/claude-code/hook.mjs'), 1);
  assert.equal(found('node /gone/elsewhere/hook.mjs'), 0, 'a file of that name, gone, on a path that names nothing of ours');
  const lone = tempFolder('provared-lone-');
  writeFileSync(join(lone, 'hook.mjs'), '');
  assert.equal(found({ type: 'command', command: 'node', args: [join(lone, 'hook.mjs')] }), 0, 'a file of that name with no recorder beside it');
  assert.deepEqual(lineWords('node "a b"/c \'d\'e f'), ['node', 'a b/c', 'de', 'f']);
});

test('before each call the plugin looks only so far: a settings file too large, too many words, or too long a look refuses the call', async () => {
  const project = tempFolder('provared-project-');
  mkdirSync(join(project, '.claude'), { recursive: true });
  const local = join(project, '.claude', 'settings.local.json');
  writeFileSync(local, JSON.stringify({ hooks: {}, padding: 'x'.repeat(1024 * 1024 + 1) }));
  assert.match(recorderHooksInSettings(project, [local]).problem, /larger than 1024 KB/);
  writeFileSync(local, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: `node ${'a '.repeat(20001)}` }] }] } }));
  assert.match(recorderHooksInSettings(project, [local]).problem, /hold too much/);
  writeFileSync(local, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'echo one' }] }] } }));
  assert.equal(recorderHooksInSettings(project, [local]).problem, null);
  assert.match(recorderHooksInSettings(project, [local], { bytes: 1 << 20, words: 100, ms: -1 }).problem, /hold too much/, 'the time limit');
  // The plugin's hook refuses the call, quickly, with what to do.
  const { folder } = await world([]);
  const service = await startService({ folder, port: 0 });
  try {
    writeFileSync(local, JSON.stringify({ hooks: {}, padding: 'x'.repeat(6 * 1024 * 1024) }));
    const started = Date.now();
    const r = await hookAsPlugin(service.port, 'PreToolUse', 'Bash', { command: 'npm test' }, asPlugin(folder, project));
    assert.ok(Date.now() - started < 10000);
    assert.equal(r.decision.permissionDecision, 'deny');
    assert.match(r.decision.permissionDecisionReason, /larger than 1024 KB/);
  } finally {
    await service.close();
  }
});

test('"remove-hooks" takes out the hooks init wrote, from any copy, and nothing else, and never over a change made meanwhile', () => {
  const project = tempFolder('provared-project-');
  const settings = join(project, '.claude', 'settings.local.json');
  mkdirSync(join(project, '.claude'), { recursive: true });
  const mine = { type: 'command', command: 'echo mine' };
  // A hook of the person's own that runs the recorder's hook and something more stays, as init leaves it.
  const wrapped = { type: 'command', command: `node "${pluginRoot}/hook.mjs" && echo more` };
  writeFileSync(settings, '\uFEFF' + JSON.stringify({ permissions: { allow: ['Read'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [mine] }, { matcher: 'Edit', hooks: [wrapped] }] } }));
  writeHooks(project);
  // An older copy's hook, written as one command line, and one of a copy since deleted.
  const older = tempFolder('provared-older-copy-');
  for (const f of ['hook.mjs', 'recorder.mjs', 'actions.mjs']) writeFileSync(join(older, f), '');
  const read = () => JSON.parse(readFileSync(settings, 'utf8').replace(/^\uFEFF/, ''));
  const s = read();
  s.hooks.PostToolUse.push({ matcher: '*', hooks: [{ type: 'command', command: `node ${join(older, 'hook.mjs')}` }] });
  s.hooks.PostToolUse.push({ matcher: '*', hooks: [{ type: 'command', command: 'node /gone/provared/integrations/claude-code/hook.mjs' }] });
  writeFileSync(settings, '\uFEFF' + JSON.stringify(s));
  // Changed between the reading and the writing: left as it is.
  assert.throws(() => removeInitHooks(project, (path, text, before) => {
    writeFileSync(path, readFileSync(path, 'utf8') + ' ');
    replaceIfUnchanged(path, text, before);
  }), /changed while it was read/);
  writeFileSync(settings, '\uFEFF' + JSON.stringify(s));
  const written = [];
  const removed = removeInitHooks(project, (path, text, before) => {
    written.push(path);
    replaceIfUnchanged(path, text, before);
  });
  assert.equal(removed.removed, 6, 'four of this copy\'s, one of the older copy\'s, one of the copy since deleted');
  assert.deepEqual(read(), { permissions: { allow: ['Read'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [mine] }, { matcher: 'Edit', hooks: [wrapped] }] } });
  assert.ok(readFileSync(settings, 'utf8').startsWith('\uFEFF'), 'the byte-order mark is kept');
  assert.ok(!existsSync(`${settings}.tmp`), 'no file left beside it');
  // Nothing left to take out: the file is not written again.
  assert.equal(removeInitHooks(project, () => assert.fail('written')).removed, 0);
  assert.equal(written.length, 1);
});

test('the start of a session, as the plugin: what the person must do where nothing is signed, the hooks in force twice, a recorder that does not start; and nothing where all is well', async () => {
  const folder = join(tempFolder(), 'claude-code');
  const project = tempFolder('provared-project-');
  const port = await freePort();
  const env = { ...asPlugin(folder, project), PROVARED_CLAUDE_CODE_PORT: String(port) };
  const start = () => runPlugin(pluginArgs('SessionStart'), { env, cwd: project });
  try {
    let r = await start();
    assert.equal(r.code, 0, r.err);
    let said = JSON.parse(r.out);
    assert.equal(said.hookSpecificOutput.hookEventName, 'SessionStart');
    assert.equal(said.systemMessage, said.hookSpecificOutput.additionalContext, 'told to the person and to Claude alike');
    assert.match(said.systemMessage, /no permission has been signed/);
    assert.match(said.systemMessage, /plugin\.mjs init/);
    assert.match(said.systemMessage, /https:\/\/sign\.prova\.red\//);
    assert.match(said.systemMessage, /plugin\.mjs use <the saved file>/);
    assert.match(said.systemMessage, /Nothing signs for you/);
    assert.doesNotMatch(said.systemMessage, /in force twice/);
    assert.ok(!existsSync(join(folder, 'agent-keys.jwk')), 'it makes no keys: init does, at the person\'s word');
    // The hook before a call says the same, in short, to Claude.
    const before = await hookAsPlugin(port, 'PreToolUse', 'Bash', { command: 'npm test' }, env);
    assert.equal(before.decision.permissionDecision, 'deny');
    assert.match(before.decision.permissionDecisionReason, /no permission has been signed for this agent yet/);
    assert.match(before.decision.permissionDecisionReason, /plugin\.mjs init/);
    assert.match(before.decision.permissionDecisionReason, /sign\.prova\.red/);
    // The hooks in force twice: said as well.
    writeHooks(project);
    said = JSON.parse((await start()).out);
    assert.match(said.systemMessage, /in force twice/);
    assert.match(said.systemMessage, /no permission has been signed/);
    removeInitHooks(project, (path, text, read) => replaceIfUnchanged(path, text, read));
    // Set up: a permission in place, and the recorder started by the start of the session, which then says nothing.
    const w = await world([]);
    cpSync(w.folder, folder, { recursive: true });
    r = await start();
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, '', 'nothing to say where all is well');
    assert.equal((await (await fetch(`http://127.0.0.1:${port}/status`)).json()).entries, 1, 'started, with the permission');
  } finally {
    await stopService(port);
  }
});

test('the start of a session says so where the recorder does not start, and keeps within the hook\'s time', async () => {
  const { folder } = await world([]);
  const project = tempFolder('provared-project-');
  // Something else answers on the port, not as the recorder: the recorder cannot start there.
  const other = createServer((req, res) => res.end('not the recorder'));
  await new Promise((r) => other.listen(0, '127.0.0.1', r));
  const env = { ...asPlugin(folder, project), PROVARED_CLAUDE_CODE_PORT: String(other.address().port) };
  try {
    const started = Date.now();
    const r = await runPlugin(pluginArgs('SessionStart'), { env, cwd: project });
    assert.ok(Date.now() - started < 29000, 'within the hook\'s 30 seconds');
    assert.equal(r.code, 0, r.err);
    const said = JSON.parse(r.out);
    assert.match(said.systemMessage, /The recorder did not start|still starting/);
    assert.match(said.systemMessage, /every tool call is refused|tool calls are refused/);
  } finally {
    await new Promise((r) => other.close(r));
  }
});

test('init, through the plugin\'s entry, with --no-hooks, or from Claude Code\'s plugin cache, writes no hooks; with anything else after it, it does nothing', async () => {
  const project = tempFolder('provared-project-');
  const folder = join(tempFolder(), 'claude-code');
  const port = await freePort();
  const home = tempFolder('provared-claude-home-');
  const env = { PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port), CLAUDE_CONFIG_DIR: home, CLAUDE_PLUGIN_DATA: dataWithLibrary() };
  const run = (script, args) => runPlugin(['--disable-warning=ExperimentalWarning', script, ...args], { cwd: project, env });
  let r = await run(join(pluginRoot, 'recorder.mjs'), ['init', '--no-hook']);
  assert.equal(r.code, 2, 'a misspelt switch writes nothing');
  assert.ok(!existsSync(join(folder, 'agent-keys.jwk')));
  r = await run(join(pluginRoot, 'recorder.mjs'), ['init', '--no-hooks']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /No hooks were written \(--no-hooks\)/);
  assert.match(r.out, /https:\/\/sign\.prova\.red\/#permission=/);
  assert.ok(!existsSync(join(project, '.claude')));
  r = await run(join(pluginRoot, 'plugin.mjs'), ['init']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /No hooks were written: this copy of the recorder is the Claude Code plugin's/);
  assert.match(r.out, /plugin\.mjs use <the saved file>/, 'the next command, through the plugin\'s entry');
  // A copy of the plugin as Claude Code installs it, in its cache, run directly.
  const cached = cachedCopy(home);
  r = await run(join(cached, 'recorder.mjs'), ['init']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /No hooks were written: this copy of the recorder is the Claude Code plugin's/);
  assert.ok(!existsSync(join(project, '.claude')));
  // init from another copy, with the plugin installed: the hooks are written, and the person is warned.
  writeFileSync(join(home, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { [`${manifest.name}@provared`]: [{ scope: 'user', installPath: cached }] } }));
  r = await run(join(pluginRoot, 'recorder.mjs'), ['init']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /The hooks are in /);
  assert.match(r.out, /Warning: the Claude Code plugin provared-recorder is installed too/);
  // remove-hooks takes them out again, and says where others are still.
  writeFileSync(join(project, '.claude', 'settings.json'), JSON.stringify({ hooks: { PostToolUse: [{ hooks: [{ type: 'command', command: `node ${relative(project, join(pluginRoot, 'hook.mjs'))}` }] }] } }));
  r = await run(join(pluginRoot, 'recorder.mjs'), ['remove-hooks']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Took 4 of the recorder's hooks out of /);
  assert.match(r.out, /other formatting in it is not kept/);
  assert.match(r.out, /still in .*settings\.json/);
  assert.deepEqual(readJson(join(project, '.claude', 'settings.local.json')), { hooks: {} });
  r = await run(join(pluginRoot, 'recorder.mjs'), ['remove-hooks']);
  assert.match(r.out, /holds none of the hooks init writes/);
});

test('paths are compared as Windows compares them there, and exactly elsewhere', () => {
  assert.equal(samePath('/a/B/c', '/a/B/c'), true);
  assert.equal(samePath('C:\\Users\\A\\x', 'c:/users/a/X'), process.platform === 'win32');
  assert.equal(samePath('/a/b', '/a/B'), process.platform === 'win32');
});

