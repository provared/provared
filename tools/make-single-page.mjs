// Writes the checking page as one file that opens in a browser with no
// server: the page, its style, the checker and the sample record, all in
// the one file. It is the same code as page/ and src/, copied in unchanged.
//
// The file allows itself no request of any kind: its content security
// policy lets nothing be loaded from anywhere, and only the script and the
// style that are in the file, named by their fingerprints, may run.
//
//   node tools/make-single-page.mjs [where to write it; provared-check.html by default]
//
// It prints the SHA-256 fingerprint of the file it wrote, so that a copy
// can be compared with it.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const START = 'page/check-page.js';
const IMPORT = /^\s*(?:import|export)\b[^;]*?\bfrom\s+'([^']+)'/gm;

const read = (path) => readFileSync(ROOT + path, 'utf8').replace(/\r\n/g, '\n');
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('base64');
// JSON that can sit inside a page: no "<" is left that could end the element it sits in.
const inPage = (value) => JSON.stringify(value).replace(/</g, '\\u003c');

function replaceOnce(text, from, to) {
  if (text.split(from).length !== 2) throw new Error(`expected exactly once in the page: ${from}`);
  return text.replace(from, () => to);
}

/**
 * The modules the page needs, each after the modules it imports. For each:
 * its path, its source exactly as it is in the repository, and where each
 * of its imports leads.
 * @returns {[string, string, Record<string, string>][]}
 */
export function pageModules() {
  const done = new Map();
  const open = new Set();
  const visit = (path) => {
    if (done.has(path)) return;
    if (open.has(path)) throw new Error(`the modules import one another in a ring at ${path}`);
    open.add(path);
    const source = read(path);
    const imports = {};
    for (const [, spec] of source.matchAll(IMPORT)) {
      imports[spec] = posix.normalize(posix.join(posix.dirname(path), spec));
      visit(imports[spec]);
    }
    open.delete(path);
    done.set(path, [path, source, imports]);
  };
  visit(START);
  return [...done.values()];
}

// The script that starts the page. Each module is made into an address of
// its own, held by the browser, with its imports pointed at the addresses of
// the modules made before it; then the page's own script is run.
const STARTER = `(async () => {
  const modules = JSON.parse(document.getElementById('modules').textContent);
  const made = new Map();
  for (const [path, source, imports] of modules) {
    let text = source;
    for (const [spec, target] of Object.entries(imports)) text = text.split("from '" + spec + "'").join("from '" + made.get(target) + "'");
    made.set(path, URL.createObjectURL(new Blob([text], { type: 'text/javascript' })));
  }
  await import(made.get(modules[modules.length - 1][0]));
})().catch(() => {
  document.getElementById('status').textContent = 'This page could not start in this browser. Use the command-line checker.';
});`;

/**
 * The checking page as the text of one file.
 * @returns {string}
 */
export function buildSinglePage() {
  const style = read('page/style.css');
  const modules = pageModules();
  const sample = { book: read('samples/office-supplies.jsonl'), expected: JSON.parse(read('samples/office-supplies.expected.json')) };
  const policy = [
    "default-src 'none'",
    `script-src 'sha256-${sha256(STARTER)}' blob:`,
    `style-src 'sha256-${sha256(style)}'`,
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');
  let page = read('page/index.html');
  page = replaceOnce(page, '<link rel="stylesheet" href="style.css">', `<meta http-equiv="Content-Security-Policy" content="${policy}">\n<style>${style}</style>`);
  page = replaceOnce(
    page,
    '<script type="module" src="check-page.js"></script>',
    [
      `<script type="application/json" id="sample-record">${inPage(sample)}</script>`,
      `<script type="application/json" id="modules">${inPage(modules)}</script>`,
      `<script>${STARTER}</script>`,
    ].join('\n'),
  );
  page = replaceOnce(
    page,
    '<p>Choose a record file. It is checked here, in this browser. Nothing is sent anywhere.</p>',
    '<p>Choose a record file. It is checked here, in this browser. Nothing is sent anywhere: this page is one file, and it allows itself no request of any kind.</p>',
  );
  return page;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = process.argv[2] ?? 'provared-check.html';
  const page = buildSinglePage();
  writeFileSync(out, page);
  console.log(`written: ${out} (${Buffer.byteLength(page)} bytes)`);
  console.log(`SHA-256: ${createHash('sha256').update(page, 'utf8').digest('hex')}`);
}
