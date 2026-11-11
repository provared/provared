// The first minutes with the command: "demo" with no passkey and no
// settings, "init", "check" listing every problem in one run, "keys"
// leaving the disk as it was when something it needs is wrong (and not
// needing the passkey's thumbprint yet), the one warning set aside, and the
// version in each place that carries it.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook } = await import('provared');
const { tempFolder } = await import('./world.mjs');
const { isPlaceholder } = await import('../executor.mjs');

const HERE = fileURLToPath(new URL('../', import.meta.url));
const BIN = join(HERE, 'bin.mjs');
const PACKAGE = JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8'));

/** Run the command in a folder, as a person would: no flag that hides warnings. */
function run(args, cwd, env = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env: { ...process.env, ...env }, windowsHide: true, timeout: 90000 });
  if (r.error) throw r.error;
  return r;
}

/**
 * The example settings and rules, copied into a folder as "init" copies
 * them (but not by it, so that each test holds on its own), with a
 * thumbprint of the right form in place of the passkey's placeholder where
 * "thumbprint" is set.
 */
function examples(folder, { http = false, thumbprint = false } = {}) {
  const name = http ? 'executor-http.json' : 'executor.json';
  let text = readFileSync(join(HERE, http ? 'executor-http.example.json' : 'executor.example.json'), 'utf8');
  if (thumbprint) text = text.replaceAll(`"<thumbprint of the person's passkey>"`,`"${'A'.repeat(43)}"`);
  writeFileSync(join(folder, name), text);
  writeFileSync(join(folder, 'content-rules.json'), readFileSync(join(HERE, 'content-rules.example.json')));
  return name;
}

/** Everything under a folder, as paths relative to it. */
function tree(folder, prefix = '') {
  return readdirSync(join(folder, prefix), { withFileTypes: true })
    .flatMap((d) => (d.isDirectory() ? [`${prefix}${d.name}/`, ...tree(folder, `${prefix}${d.name}/`)] : [`${prefix}${d.name}`]))
    .sort();
}

test('demo: with no passkey and no settings, one call is let through, one is refused, and the book checks clean; all of it in a new temporary folder', async () => {
  const temporary = tempFolder();
  const here = tempFolder();
  const r = run(['demo'], here, { TMPDIR: temporary, TEMP: temporary, TMP: temporary });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^DEMONSTRATION ONLY\. .*development stand-in for a passkey.*"\(development\)"/);
  assert.doesNotMatch(r.stdout, /FAIL/);
  assert.match(r.stdout, /ok +echo "hello": let through/);
  assert.match(r.stdout, /ok +echo "my password is swordfish": refused and not sent on/);
  assert.match(r.stdout, /ok +4\. The book, checked with the Provared checker: it checks clean/);
  assert.doesNotMatch(r.stderr, /ExperimentalWarning/);

  // Nothing in the folder it was run in; one new folder in the temporary folder, which it named.
  assert.deepEqual(readdirSync(here), []);
  const made = readdirSync(temporary);
  assert.equal(made.length, 1);
  assert.match(made[0], /^provared-mcp-demo-/);
  const folder = join(temporary, made[0]);
  assert.ok(r.stdout.includes(folder), 'the folder is named');

  const settings = JSON.parse(readFileSync(join(folder, 'executor.json'), 'utf8'));
  const result = await checkBook(readFileSync(join(folder, 'book.jsonl'), 'utf8'), { issuerKeys: settings.agent.issuerKeys });
  assert.equal(result.summary.intact, true);
  assert.equal(result.summary.fullyChecked, true);
  assert.equal(result.summary.withinSlips, true);
  assert.deepEqual(result.entries.map((e) => e.kind), ['slip', 'stub', 'denial']);
  assert.equal(result.entries[1].countersignature.state, 'valid');
  const slip = JSON.parse(readFileSync(join(folder, 'slip.json'), 'utf8'));
  assert.match(JSON.parse(Buffer.from(slip.payload, 'base64url').toString('utf8')).issuer.name, /\(development\)$/);
});

test('init: copies the example settings and rules into the folder, byte for byte, and overwrites nothing', () => {
  const folder = tempFolder();
  const r = run(['init'], folder);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(tree(folder), ['content-rules.json', 'executor.json']);
  assert.equal(readFileSync(join(folder, 'executor.json'), 'utf8'), readFileSync(join(HERE, 'executor.example.json'), 'utf8'));
  assert.equal(readFileSync(join(folder, 'content-rules.json'), 'utf8'), readFileSync(join(HERE, 'content-rules.example.json'), 'utf8'));
  assert.match(r.stdout, /keys --config executor\.json/);

  // A second run, or one where one of the two files is there: nothing is written.
  writeFileSync(join(folder, 'executor.json'), 'mine');
  const again = run(['init'], folder);
  assert.equal(again.status, 2);
  assert.match(again.stderr, /Nothing was written/);
  assert.equal(readFileSync(join(folder, 'executor.json'), 'utf8'), 'mine');

  const other = tempFolder();
  writeFileSync(join(other, 'content-rules.json'), 'mine');
  const partly = run(['init'], other);
  assert.equal(partly.status, 2);
  assert.deepEqual(tree(other), ['content-rules.json'], 'executor.json is not written either');

  const http = tempFolder();
  assert.equal(run(['init', '--http'], http).status, 0);
  assert.deepEqual(tree(http), ['content-rules.json', 'executor-http.json']);
  assert.equal(readFileSync(join(http, 'executor-http.json'), 'utf8'), readFileSync(join(HERE, 'executor-http.example.json'), 'utf8'));
});

test('the example settings agree with the example rules: every tool a rule on content names has a rule in "tools"', () => {
  const rules = JSON.parse(readFileSync(join(HERE, 'content-rules.example.json'), 'utf8')).rules;
  for (const file of ['executor.example.json', 'executor-http.example.json']) {
    const config = JSON.parse(readFileSync(join(HERE, file), 'utf8'));
    assert.equal(config.contentRules, 'content-rules.json', `${file} names the file init writes`);
    for (const rule of rules) for (const tool of [rule.tool].flat()) assert.ok(Object.hasOwn(config.tools, tool), `${file}: "${tool}" has a rule in "tools"`);
  }
});

test('check lists every problem it finds in one run: each placeholder left, the missing rules file, both key files and the slip', () => {
  const folder = tempFolder();
  examples(folder);
  writeFileSync(join(folder, 'content-rules.json'), '');
  const r = run(['check', '--config', 'executor.json'], folder);
  assert.equal(r.status, 1);
  assert.doesNotMatch(r.stderr, /ExperimentalWarning/);
  const { problems } = JSON.parse(r.stdout);
  const expected = [/^server\.args\[0\]: still holds the example's placeholder/, /^server\.cwd: still holds the example's placeholder/, /^server\.env\.FILES_API_TOKEN\.file: still holds the example's placeholder/, /^agent\.issuerKeys\[0\]: still holds the example's placeholder/, /rules file .*content-rules\.json \(contentRules\) is missing or empty/, /^executor\.keys: the key file .*executor\.jwk does not exist yet/, /^agent\.keys: the key file .*agent\.jwk does not exist yet/, /^agent\.slip: the slip .*slip\.json is missing/];
  for (const e of expected) assert.ok(problems.some((p) => e.test(p)), `${e} among:\n${problems.join('\n')}`);
  assert.equal(problems.length, expected.length, problems.join('\n'));
  assert.deepEqual(tree(folder), ['content-rules.json', 'executor.json'], 'check writes nothing');
});

test('check over HTTP lists every problem in one run too', () => {
  const folder = tempFolder();
  examples(folder, { http: true });
  const { problems } = JSON.parse(run(['check', '--config', 'executor-http.json'], folder).stdout);
  for (const e of [/^upstream\.credential\.file: still holds/, /^agents\.research\.secretHash: still holds/, /^agents\.ordering\.issuerKeys\[0\]: still holds/, /^executor\.keys: the key file/, /^agents\.research\.keys: the key file/, /^agents\.ordering\.slip: the slip/]) {
    assert.ok(problems.some((p) => e.test(p)), `${e} among:\n${problems.join('\n')}`);
  }
});

test('a placeholder is a whole text in angle brackets with a space in it, so that an argument such as "<json>" is not one', () => {
  assert.equal(isPlaceholder("<thumbprint of the person's passkey>"), true);
  assert.equal(isPlaceholder('<json>'), false);
  assert.equal(isPlaceholder('a <b c> d'), false);
  assert.equal(isPlaceholder('files-server.mjs'), false);
});

test('keys needs no passkey thumbprint yet, says in one line what to do with what it prints, and can write it to a new file', () => {
  const folder = tempFolder();
  examples(folder);
  const r = run(['keys', '--config', 'executor.json'], folder);
  assert.equal(r.status, 0, r.stderr);
  const printed = JSON.parse(r.stdout);
  assert.equal(printed.with.id, 'executor');
  assert.deepEqual(printed.requires, [{ need: 'countersignature' }]);
  assert.equal(r.stderr.trim().split('\n').length, 1, `one line, and no warning:\n${r.stderr}`);
  assert.match(r.stderr, /^provared-mcp-executor: What to do with this: it goes into the permission/);

  const out = run(['keys', '--config', 'executor.json', '--out', 'for-the-permission.json'], folder);
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout, '');
  assert.deepEqual(JSON.parse(readFileSync(join(folder, 'for-the-permission.json'), 'utf8')), printed, 'the same keys, read again');
  const twice = run(['keys', '--config', 'executor.json', '--out', 'for-the-permission.json'], folder);
  assert.equal(twice.status, 2);
  assert.match(twice.stderr, /already exists/);
});

test('keys writes nothing when something it needs is wrong: a missing rules file, a key file that cannot be read, a folder for --out that is not there', () => {
  const missingRules = tempFolder();
  examples(missingRules, { thumbprint: true });
  writeFileSync(join(missingRules, 'content-rules.json'), '');
  const a = run(['keys', '--config', 'executor.json'], missingRules);
  assert.equal(a.status, 2);
  assert.match(a.stderr, /is missing or empty/);
  assert.deepEqual(tree(missingRules), ['content-rules.json', 'executor.json'], 'no key file was made');

  const badKey = tempFolder();
  examples(badKey, { thumbprint: true });
  mkdirSync(join(badKey, 'keys'));
  writeFileSync(join(badKey, 'keys', 'agent.jwk'), 'not a key file');
  const b = run(['keys', '--config', 'executor.json'], badKey);
  assert.equal(b.status, 2);
  assert.match(b.stderr, /agent\.jwk could not be read as a key file/);
  assert.equal(existsSync(join(badKey, 'keys', 'executor.jwk')), false, "the executor's key file was not made");

  const noFolder = tempFolder();
  examples(noFolder, { thumbprint: true });
  const c = run(['keys', '--config', 'executor.json', '--out', join('not-there', 'out.json')], noFolder);
  assert.equal(c.status, 2);
  assert.match(c.stderr, /Nothing was written/);
  assert.deepEqual(tree(noFolder), ['content-rules.json', 'executor.json']);
});

test("only Node.js's notice that ML-DSA-87 is experimental is set aside; every other warning is printed", () => {
  const quiet = new URL('../quiet.mjs', import.meta.url).href;
  const code = [
    `await import(${JSON.stringify(quiet)});`,
    "process.emitWarning('The ML-DSA-87 Web Crypto API algorithm is an experimental feature and might change at any time', 'ExperimentalWarning');",
    "process.emitWarning('The SLH-DSA-SHA2-256s algorithm is an experimental feature', 'ExperimentalWarning');",
    "process.emitWarning('Something else is experimental', { type: 'ExperimentalWarning' });",
    "process.emitWarning('The ML-DSA-87 Web Crypto API algorithm is an experimental feature, said as another kind', 'DeprecationWarning');",
    "process.emitWarning('A warning of its own');",
  ].join('\n');
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', windowsHide: true });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /ExperimentalWarning: The ML-DSA-87/);
  assert.match(r.stderr, /ExperimentalWarning: The SLH-DSA-SHA2-256s/);
  assert.match(r.stderr, /ExperimentalWarning: Something else is experimental/);
  assert.match(r.stderr, /DeprecationWarning: The ML-DSA-87/);
  assert.match(r.stderr, /Warning: A warning of its own/);
});

test('the version: --version, server.json and the package agree', () => {
  const r = run(['--version'], tempFolder());
  assert.equal(r.stdout, `provared-mcp-executor ${PACKAGE.version}\n`);
  const server = JSON.parse(readFileSync(join(HERE, 'server.json'), 'utf8'));
  assert.equal(server.version, PACKAGE.version);
  assert.equal(server.packages[0].version, PACKAGE.version);
});

test('the package holds every file the command loads, and the demonstration\'s server and rules', () => {
  const files = new Set(PACKAGE.files);
  for (const f of ['bin.mjs', 'quiet.mjs', 'demo.mjs', 'demo/server.mjs', 'demo/content-rules.json', 'executor.example.json', 'executor-http.example.json', 'content-rules.example.json']) assert.ok(files.has(f), f);
  for (const f of PACKAGE.files.filter((x) => x.endsWith('.mjs'))) {
    for (const m of readFileSync(join(HERE, f), 'utf8').matchAll(/from '\.\/([^']+)'|import\('\.\/([^']+)'\)|import '\.\/([^']+)'/g)) {
      const name = m.slice(1).find(Boolean);
      assert.ok(files.has(name), `${f} loads ./${name}, which is in the package`);
    }
  }
});
