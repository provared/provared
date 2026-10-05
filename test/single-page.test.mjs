// The checking page built as a single file (tools/make-single-page.mjs): it
// holds the page, its style, the checker and the sample record, unchanged,
// and allows itself no request of any kind.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { buildSinglePage, pageModules } from '../tools/make-single-page.mjs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('base64');
const block = (page, id) => JSON.parse(page.match(new RegExp(`<script type="application/json" id="${id}">([^<]*)</script>`))[1]);

test('the single-file page holds the checker\'s own files, unchanged, each after the files it imports', () => {
  const page = buildSinglePage();
  const modules = block(page, 'modules');
  assert.deepEqual(modules, pageModules());
  const seen = new Set();
  for (const [path, source, imports] of modules) {
    assert.equal(source, read(path), path);
    for (const target of Object.values(imports)) assert.ok(seen.has(target), `${path} imports ${target}, which must come before it`);
    seen.add(path);
  }
  // The page's own script is the last, and the one that is started.
  assert.equal(modules.at(-1)[0], 'page/check-page.js');
  assert.ok(seen.has('src/check.js') && seen.has('src/book.js') && seen.has('page/render.js'));
  // Nothing that writes records for an agent is in it.
  for (const path of ['src/recorder.js', 'src/guard.js', 'src/tools.js', 'src/index.js', 'src/passkey-browser.js']) assert.ok(!seen.has(path), path);
});

test('the single-file page refers to nothing outside itself, and its policy lets nothing be loaded', () => {
  const page = buildSinglePage();
  // No file is referred to: no style sheet, no script and no image by address.
  assert.doesNotMatch(page, /<link\b/);
  assert.doesNotMatch(page, /<script[^>]*\bsrc=/);
  assert.doesNotMatch(page, /<(img|iframe|object|embed|video|audio|source)\b/);
  // The policy: nothing from anywhere; only the one script and the one style in the file, by their fingerprints.
  const policy = page.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1];
  const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];
  const style = page.match(/<style>([\s\S]*?)<\/style>/)[1];
  assert.equal(policy, `default-src 'none'; script-src 'sha256-${sha256(script)}' blob:; style-src 'sha256-${sha256(style)}'; base-uri 'none'; form-action 'none'`);
  assert.equal(style, read('page/style.css'));
  assert.equal([...page.matchAll(/<script>/g)].length, 1);
  assert.equal([...page.matchAll(/<style>/g)].length, 1);
  // The policy comes before anything that could run or be loaded.
  assert.ok(page.indexOf('Content-Security-Policy') < page.indexOf('<style>'));
  assert.ok(page.indexOf('Content-Security-Policy') < page.indexOf('<script'));
  assert.match(page, /Evidence, not a verdict/);
  assert.match(page, /it allows itself no request of any kind/);
});

test('the single-file page holds the sample record, and is the same every time it is built', () => {
  const page = buildSinglePage();
  const sample = block(page, 'sample-record');
  assert.equal(sample.book, read('samples/office-supplies.jsonl'));
  assert.deepEqual(sample.expected, JSON.parse(read('samples/office-supplies.expected.json')));
  assert.equal(buildSinglePage(), page);
  // What is held as data cannot end the element it sits in.
  for (const id of ['modules', 'sample-record']) {
    const held = page.slice(page.indexOf(`id="${id}">`), page.indexOf('</script>', page.indexOf(`id="${id}">`)));
    assert.ok(!held.includes('<'), id);
  }
});
