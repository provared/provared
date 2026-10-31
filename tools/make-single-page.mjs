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
// It has no options: an argument that begins with "-", or more than one
// argument, stops it with code 2 and nothing written.
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
 * The modules a page needs, each after the modules it imports. For each:
 * its path, its source exactly as it is in the repository, and where each
 * of its imports leads. The checking page's by default; the signing page's
 * for tools/make-sign-site.mjs, which hands in a way of reading each file
 * at a tag or commit, so that the modules are those of that commit.
 * @param {string} [start] the page's own script, as a path from the repository's top
 * @param {(path: string) => string} [readSource] how a file is read; this repository's working tree by default
 * @returns {[string, string, Record<string, string>][]}
 */
export function pageModules(start = START, readSource = read) {
  const done = new Map();
  const open = new Set();
  const visit = (path) => {
    if (done.has(path)) return;
    if (open.has(path)) throw new Error(`the modules import one another in a ring at ${path}`);
    open.add(path);
    const source = readSource(path);
    const imports = {};
    for (const [, spec] of source.matchAll(IMPORT)) {
      imports[spec] = posix.normalize(posix.join(posix.dirname(path), spec));
      visit(imports[spec]);
    }
    open.delete(path);
    done.set(path, [path, source, imports]);
  };
  visit(start);
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

/**
 * Where to write the page, from the command's arguments: none (the default
 * name), or one path. Anything else is refused, so that an option such as
 * `--out x`, which this tool does not have, is never taken as a file name.
 * @param {string[]} args the arguments after the script's own name
 * @returns {string}
 */
export function outputPath(args) {
  if (args.length === 0) return 'provared-check.html';
  const option = args.find((arg) => arg.startsWith('-'));
  if (option !== undefined) throw new Error(`this tool has no options, so "${option}" is not taken as a file name. Give no argument to write provared-check.html, or give the path of the file to write.`);
  if (args.length > 1) throw new Error(`this tool takes at most one argument, the file to write, and was given ${args.length}.`);
  if (args[0] === '') throw new Error('the file to write was given as an empty name.');
  return args[0];
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let out;
  try {
    out = outputPath(process.argv.slice(2));
  } catch (error) {
    console.error(`Stopped: ${error.message} Nothing was written.`);
    process.exit(2);
  }
  const page = buildSinglePage();
  writeFileSync(out, page);
  console.log(`written: ${out} (${Buffer.byteLength(page)} bytes)`);
  console.log(`SHA-256: ${createHash('sha256').update(page, 'utf8').digest('hex')}`);
}
