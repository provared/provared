// The tool that writes the signing page's own site (tools/make-sign-site.mjs):
// every file it writes under site/ is a byte-for-byte copy of a file as git
// holds it at the tag or commit named with --from, never the working tree;
// every module the page loads is among them; the list of fingerprints is
// what "sha256sum --check" reads; the repository's own files name where the
// copies come from; a name git cannot find is refused; and a folder that
// holds anything else is refused.
//
// Most tests run on a small repository made for the test, with a tag of its
// own, so that they need neither the tags of this repository nor its full
// history (the tests on GitHub run on a copy with one commit and no tags).

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { pageModules } from '../tools/make-single-page.mjs';
import { SITE_NAME, checkName, checkSite, copiedFiles, fingerprintList, servedAt, siteFiles, sourceAt, sourceWords, writeSite } from '../tools/make-sign-site.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TOOL = join(ROOT, 'tools', 'make-sign-site.mjs');
const git = (repo, ...args) => execFileSync('git', ['-C', repo, '-c', 'core.autocrlf=false', ...args], { stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8').trim();
const shown = (repo, at, path) => execFileSync('git', ['-C', repo, 'show', `${at}:${path}`]);
const commitAll = (repo, message) => {
  git(repo, 'add', '-A');
  git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', message);
};

// A repository made for the test: the signing page's files, the library's
// modules, the licence and the publishing workflow, copied from this
// repository's working tree, committed once and tagged v0.6.0. Made once
// and shared by the tests that do not change it, since git is slow on some
// computers.
function fixture() {
  const repo = mkdtempSync(join(tmpdir(), 'provared-sign-repo-'));
  const copy = (path) => {
    mkdirSync(join(repo, ...path.split('/').slice(0, -1)), { recursive: true });
    cpSync(join(ROOT, ...path.split('/')), join(repo, ...path.split('/')));
  };
  for (const path of ['page/sign.html', 'page/sign-page.js', 'page/render.js', 'page/style.css', 'LICENSE', '.github/workflows/pages.yml']) copy(path);
  for (const name of readdirSync(join(ROOT, 'src')).filter((n) => n.endsWith('.js'))) copy(`src/${name}`);
  // A file under src/ that is not a module, and a module in a folder below src/: neither is copied.
  writeFileSync(join(repo, 'src', 'notes.txt'), 'not a module\n');
  mkdirSync(join(repo, 'src', 'deeper'), { recursive: true });
  writeFileSync(join(repo, 'src', 'deeper', 'inner.js'), 'export const inner = 1;\n');
  git(repo, 'init', '-q');
  commitAll(repo, 'fixture');
  git(repo, 'tag', 'v0.6.0');
  return repo;
}
let shared = null;
const sharedFixture = () => (shared ??= fixture());

test('every file under site/ is a copy of a file as git holds it at the tag: the page as index.html, its script, the renderer, the style sheet, and every module of the library', () => {
  const repo = sharedFixture();
  const copies = copiedFiles('v0.6.0', repo);
  assert.equal(copies['index.html'], 'page/sign.html');
  assert.equal(copies['sign-page.js'], 'page/sign-page.js');
  assert.equal(copies['render.js'], 'page/render.js');
  assert.equal(copies['style.css'], 'page/style.css');
  const modules = readdirSync(join(repo, 'src')).filter((n) => n.endsWith('.js')).sort();
  assert.ok(modules.length > 20);
  for (const name of modules) assert.equal(copies[`src/${name}`], `src/${name}`);
  assert.equal(Object.keys(copies).length, 4 + modules.length, 'nothing else: not src/notes.txt, not src/deeper/inner.js');
  // Every module the page's script imports is served, at the path its import reaches from the site's root.
  for (const [path] of pageModules('page/sign-page.js')) assert.equal(copies[servedAt(path)], path, path);
  assert.throws(() => servedAt('net/nodes.js'), /no place on the site/);
  const files = siteFiles('v0.6.0', repo);
  for (const [served, path] of Object.entries(copies)) assert.ok(Buffer.from(files[`site/${served}`]).equals(readFileSync(join(repo, ...path.split('/')))), served);
  assert.ok(Buffer.from(files['site/src/check.js']).equals(shown(repo, 'v0.6.0', 'src/check.js')));
  assert.ok(Buffer.from(files.LICENSE).equals(shown(repo, 'v0.6.0', 'LICENSE')));
  assert.deepEqual(Object.keys(files).sort(), ['.github/workflows/pages.yml', 'LICENSE', 'README.md', 'site/files.sha256', ...Object.keys(copies).map((s) => `site/${s}`)].sort());
});

test('in this repository, at its own commit, the copies are the files git holds there', () => {
  const head = git(ROOT, 'rev-parse', 'HEAD');
  const source = sourceAt(head);
  const copies = copiedFiles(source);
  const modules = git(ROOT, 'ls-tree', '--name-only', head, '--', 'src/').split('\n').filter((p) => p.endsWith('.js')).sort();
  assert.deepEqual(Object.keys(copies).filter((s) => s.startsWith('src/')).sort(), modules);
  for (const path of ['page/sign.html', 'src/check.js', 'LICENSE']) assert.ok(source.show(path).equals(shown(ROOT, head, path)), path);
});

test('a file not committed, or changed and not committed, does not reach the site: the files are those of the tag', () => {
  const repo = fixture();
  const folder = mkdtempSync(join(tmpdir(), 'provared-sign-site-'));
  writeSite(folder, 'v0.6.0', repo);
  // A stray module nobody committed, and changes nobody committed to a copied module, to the page and to the licence.
  writeFileSync(join(repo, 'src', 'zzz.js'), 'export const stray = true;\n');
  writeFileSync(join(repo, 'src', 'check.js'), `${readFileSync(join(repo, 'src', 'check.js'), 'utf8')}\nexport const changed = true;\n`);
  writeFileSync(join(repo, 'page', 'sign.html'), '<p>changed and not committed</p>\n');
  writeFileSync(join(repo, 'LICENSE'), 'changed\n');
  const files = siteFiles('v0.6.0', repo);
  assert.ok(!Object.hasOwn(files, 'site/src/zzz.js'), 'the stray file is not copied');
  assert.doesNotMatch(String(files['site/files.sha256']), /zzz\.js/);
  assert.ok(Buffer.from(files['site/src/check.js']).equals(shown(repo, 'v0.6.0', 'src/check.js')));
  assert.doesNotMatch(String(files['site/src/check.js']), /changed = true/);
  assert.ok(Buffer.from(files['site/index.html']).equals(shown(repo, 'v0.6.0', 'page/sign.html')));
  assert.ok(Buffer.from(files.LICENSE).equals(shown(repo, 'v0.6.0', 'LICENSE')));
  // The folder written before the changes is still the tag's, byte for byte.
  assert.deepEqual(checkSite(folder, 'v0.6.0', repo), []);
  // Committed later, a module reaches the site only from that commit on.
  commitAll(repo, 'later');
  assert.ok(!Object.hasOwn(siteFiles('v0.6.0', repo), 'site/src/zzz.js'), 'not at the tag');
  assert.ok(Object.hasOwn(siteFiles('HEAD', repo), 'site/src/zzz.js'), 'at the later commit');
});

test('a name git cannot find is refused, and nothing is written or compared; a name that is not one is refused', () => {
  const repo = sharedFixture();
  const folder = mkdtempSync(join(tmpdir(), 'provared-sign-site-'));
  for (const unknown of ['v9.9.9', '0123456789abcdef0123456789abcdef01234567']) {
    assert.throws(() => sourceAt(unknown, repo), /git finds no tag or commit named .* so nothing was written or compared/, unknown);
    assert.throws(() => writeSite(folder, unknown, repo), /git finds no tag or commit/);
    assert.throws(() => checkSite(folder, unknown, repo), /git finds no tag or commit/);
  }
  assert.deepEqual(readdirSync(folder), [], 'nothing written');
  for (const bad of ['', '-v', '--output=x', '.hidden', 'v0.6.0 or so', 'a/b', 'v0.6.0^{tree}', 42, undefined]) {
    assert.throws(() => checkName(bad), /--from names a tag/, String(bad));
    assert.throws(() => sourceAt(bad, repo), /--from names a tag/, String(bad));
  }
  // From the command line: refused with code 2, and the folder stays empty.
  let failed = null;
  try {
    execFileSync(process.execPath, [TOOL, folder, '--from', 'v9.9.9'], { stdio: ['ignore', 'pipe', 'pipe'], cwd: ROOT });
  } catch (e) {
    failed = e;
  }
  assert.ok(failed, 'the command fails');
  assert.equal(failed.status, 2);
  assert.match(String(failed.stderr), /git finds no tag or commit named v9\.9\.9/);
  assert.equal(existsSync(join(folder, 'site')), false);
});

test('the list of fingerprints is one line for each copied file, in the form sha256sum --check reads, sorted by path, and names every copy and nothing else', () => {
  const repo = sharedFixture();
  const files = siteFiles('v0.6.0', repo);
  const list = String(files['site/files.sha256']);
  const lines = list.split('\n');
  assert.equal(lines.at(-1), '', 'ends with a line break');
  const entries = lines.slice(0, -1).map((line) => {
    const m = /^([0-9a-f]{64}) \*\.\/(.+)$/.exec(line);
    assert.ok(m, line);
    return [m[2], m[1]];
  });
  const copied = Object.keys(copiedFiles('v0.6.0', repo)).sort();
  assert.deepEqual(entries.map(([path]) => path), copied);
  for (const [path, hash] of entries) assert.equal(hash, createHash('sha256').update(files[`site/${path}`]).digest('hex'), path);
  assert.equal(fingerprintList({ 'b.js': Buffer.from('b'), 'a.js': Buffer.from('a') }), `${createHash('sha256').update('a').digest('hex')} *./a.js\n${createHash('sha256').update('b').digest('hex')} *./b.js\n`);
});

test('the README and the workflow name where the copies come from, a tag by its name or a commit by its full hash, and the workflow pins the actions the repository pins', () => {
  const repo = sharedFixture();
  const commit = git(repo, 'rev-parse', 'HEAD');
  assert.deepEqual(sourceWords({ tag: 'v0.6.0', commit }), { plain: 'tag v0.6.0', marked: 'tag `v0.6.0`' });
  assert.deepEqual(sourceWords({ tag: null, commit }), { plain: `commit ${commit}`, marked: `commit \`${commit}\`` });
  assert.equal(sourceAt('v0.6.0', repo).tag, 'v0.6.0');
  // A name that is not a tag is named by the full hash of the commit git finds for it.
  for (const name of [commit.slice(0, 7), 'HEAD']) {
    const at = sourceAt(name, repo);
    assert.equal(at.tag, null, name);
    assert.equal(at.commit, commit, name);
  }
  const tagged = siteFiles('v0.6.0', repo);
  assert.match(String(tagged['README.md']), /the same file at tag `v0\.6\.0` of\n  https:\/\/github\.com\/provared\/provared/);
  assert.match(String(tagged['.github/workflows/pages.yml']), /the same file at tag v0\.6\.0 of provared\/provared/);
  assert.match(String(tagged['README.md']), new RegExp(`^# ${SITE_NAME.replace('.', '\\.')}\n`));
  const committed = siteFiles(commit.slice(0, 7), repo);
  assert.ok(String(committed['README.md']).includes(`at commit \`${commit}\` of`));
  const own = shown(repo, 'v0.6.0', '.github/workflows/pages.yml').toString('utf8');
  const workflow = String(tagged['.github/workflows/pages.yml']);
  for (const name of ['checkout', 'configure-pages', 'upload-pages-artifact', 'deploy-pages']) {
    const pin = own.match(new RegExp(`uses: actions/${name}@[0-9a-f]{40} # v[0-9.]+`))[0];
    assert.ok(workflow.includes(pin), pin);
  }
  assert.match(workflow, /sha256sum --check --strict files\.sha256/);
  assert.match(workflow, /path: site\n/);
  assert.doesNotMatch(workflow, /setup-node|npm/, 'nothing is built on the way');
});

test('written into an empty folder, the folder then checks; a file from elsewhere is reported, and a folder that holds one is refused', () => {
  const repo = sharedFixture();
  const commit = git(repo, 'rev-parse', 'HEAD');
  const folder = mkdtempSync(join(tmpdir(), 'provared-sign-site-'));
  const written = writeSite(folder, 'v0.6.0', repo);
  assert.deepEqual(written, Object.keys(siteFiles('v0.6.0', repo)).sort());
  assert.deepEqual(checkSite(folder, 'v0.6.0', repo), []);
  assert.deepEqual(checkSite(folder, commit, repo), ['differs: .github/workflows/pages.yml', 'differs: README.md'], 'the source named is part of what is checked');
  // Written again over itself: the same.
  writeSite(folder, 'v0.6.0', repo);
  assert.deepEqual(checkSite(folder, 'v0.6.0', repo), []);
  writeFileSync(join(folder, 'site', 'extra.html'), '<p>not from the repository</p>');
  assert.deepEqual(checkSite(folder, 'v0.6.0', repo), ['not from this repository: site/extra.html']);
  assert.throws(() => writeSite(folder, 'v0.6.0', repo), /holds files this tool does not write, so nothing was written: site\/extra\.html/);
  writeFileSync(join(folder, 'site', 'index.html'), 'changed');
  const differences = checkSite(folder, 'v0.6.0', repo);
  assert.ok(differences.includes('differs: site/index.html'));
  assert.ok(differences.includes('not from this repository: site/extra.html'));
});
