// The tool that writes the signing page's own site (tools/make-sign-site.mjs):
// every file it writes under site/ is a byte-for-byte copy of a file here,
// every module the page loads is among them, the list of fingerprints is
// what "sha256sum --check" reads, the repository's own files name where the
// copies come from, and a folder that holds anything else is refused.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pageModules } from '../tools/make-single-page.mjs';
import { SITE_NAME, checkSite, copiedFiles, fingerprintList, servedAt, siteFiles, sourceWords, writeSite } from '../tools/make-sign-site.mjs';

const ROOT = new URL('..', import.meta.url);
const here = (path) => readFileSync(new URL(path, ROOT));

test('every file under site/ is a copy of a file here: the page as index.html, its script, the renderer, the style sheet, and every module of the library', () => {
  const copies = copiedFiles();
  assert.equal(copies['index.html'], 'page/sign.html');
  assert.equal(copies['sign-page.js'], 'page/sign-page.js');
  assert.equal(copies['render.js'], 'page/render.js');
  assert.equal(copies['style.css'], 'page/style.css');
  const modules = readdirSync(new URL('src/', ROOT)).filter((n) => n.endsWith('.js')).sort();
  assert.ok(modules.length > 20);
  for (const name of modules) assert.equal(copies[`src/${name}`], `src/${name}`);
  assert.equal(Object.keys(copies).length, 4 + modules.length, 'nothing else');
  // Every module the page's script imports is served, at the path its import reaches from the site's root.
  for (const [path] of pageModules('page/sign-page.js')) assert.equal(copies[servedAt(path)], path, path);
  assert.throws(() => servedAt('net/nodes.js'), /no place on the site/);
  const files = siteFiles('v0.6.0');
  for (const [served, path] of Object.entries(copies)) assert.ok(Buffer.from(files[`site/${served}`]).equals(here(path)), served);
  assert.ok(Buffer.from(files.LICENSE).equals(here('LICENSE')));
  assert.deepEqual(Object.keys(files).sort(), ['.github/workflows/pages.yml', 'LICENSE', 'README.md', 'site/files.sha256', ...Object.keys(copies).map((s) => `site/${s}`)].sort());
});

test('the list of fingerprints is one line for each copied file, in the form sha256sum --check reads, sorted by path, and names every copy and nothing else', () => {
  const files = siteFiles('v0.6.0');
  const list = String(files['site/files.sha256']);
  const lines = list.split('\n');
  assert.equal(lines.at(-1), '', 'ends with a line break');
  const entries = lines.slice(0, -1).map((line) => {
    const m = /^([0-9a-f]{64}) \*\.\/(.+)$/.exec(line);
    assert.ok(m, line);
    return [m[2], m[1]];
  });
  const copied = Object.keys(copiedFiles()).sort();
  assert.deepEqual(entries.map(([path]) => path), copied);
  for (const [path, hash] of entries) assert.equal(hash, createHash('sha256').update(files[`site/${path}`]).digest('hex'), path);
  assert.equal(fingerprintList({ 'b.js': Buffer.from('b'), 'a.js': Buffer.from('a') }), `${createHash('sha256').update('a').digest('hex')} *./a.js\n${createHash('sha256').update('b').digest('hex')} *./b.js\n`);
});

test('the README and the workflow name where the copies come from, a tag or a commit, and the workflow pins the actions this repository pins', () => {
  assert.deepEqual(sourceWords('v0.6.0'), { plain: 'tag v0.6.0', marked: 'tag `v0.6.0`' });
  assert.deepEqual(sourceWords('e4dd2f0'), { plain: 'commit e4dd2f0', marked: 'commit `e4dd2f0`' });
  for (const bad of ['', 'v0.6.0 or so', 'a/b', 42, undefined]) assert.throws(() => sourceWords(bad), /--from names a tag/);
  const tagged = siteFiles('v0.6.0');
  assert.match(String(tagged['README.md']), /the same file at tag `v0\.6\.0` of\n  https:\/\/github\.com\/provared\/provared/);
  assert.match(String(tagged['.github/workflows/pages.yml']), /the same file at tag v0\.6\.0 of provared\/provared/);
  assert.match(String(tagged['README.md']), new RegExp(`^# ${SITE_NAME.replace('.', '\\.')}\n`));
  const committed = siteFiles('e4dd2f0');
  assert.match(String(committed['README.md']), /at commit `e4dd2f0` of/);
  const own = readFileSync(new URL('.github/workflows/pages.yml', ROOT), 'utf8');
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
  const folder = mkdtempSync(join(tmpdir(), 'provared-sign-site-'));
  const written = writeSite(folder, 'v0.6.0');
  assert.deepEqual(written, Object.keys(siteFiles('v0.6.0')).sort());
  assert.deepEqual(checkSite(folder, 'v0.6.0'), []);
  assert.deepEqual(checkSite(folder, 'e4dd2f0'), ['differs: .github/workflows/pages.yml', 'differs: README.md'], 'the source named is part of what is checked');
  // Written again over itself: the same.
  writeSite(folder, 'v0.6.0');
  assert.deepEqual(checkSite(folder, 'v0.6.0'), []);
  writeFileSync(join(folder, 'site', 'extra.html'), '<p>not from the repository</p>');
  assert.deepEqual(checkSite(folder, 'v0.6.0'), ['not from this repository: site/extra.html']);
  assert.throws(() => writeSite(folder, 'v0.6.0'), /holds files this tool does not write, so nothing was written: site\/extra\.html/);
  writeFileSync(join(folder, 'site', 'index.html'), 'changed');
  const differences = checkSite(folder, 'v0.6.0');
  assert.ok(differences.includes('differs: site/index.html'));
  assert.ok(differences.includes('not from this repository: site/extra.html'));
});
