// Writes the files of the signing page's own site, sign.prova.red, which a
// second public repository (provared/sign) publishes with GitHub Pages: the
// signing page and only the files it loads, each copied byte for byte from
// this repository, and the few files that site needs of its own (the name it
// is served at, the workflow that publishes it, a README and the licences).
//
//   node tools/make-sign-site.mjs <folder>          write the site into the folder (it may hold a .git folder and
//                                                   what this tool wrote before, nothing else)
//   node tools/make-sign-site.mjs <folder> --check  compare a folder written before with this repository as it
//                                                   stands, and fail where anything differs
//
// Why a site of its own: a passkey can be asked to sign by any page under
// the website name it was made for, and what it signs is a fingerprint the
// person cannot read on the device's prompt. A passkey made at
// sign.prova.red can be asked to sign only by a page under that name, and
// that name serves nothing but this page (format description, section 4.4;
// the list of threats, section 3). The pages at prova.red stay where they
// are, and prova.red/sign/ says that signing has moved.
//
// How the files are laid out: the page is index.html at the site's root,
// beside its script, the renderer and the style sheet, and the library's
// modules are under src/. The page's script imports "../src/check.js"; from
// an address at the site's root, "../" stays at the root, so that import
// reaches /src/check.js, and nothing in any copied file is changed.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, posix, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pageModules } from './make-single-page.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
/** The name the site is served at. */
export const SITE_NAME = 'sign.prova.red';
/** The page's own script, from which the modules it loads are found. */
const START = 'page/sign-page.js';

const read = (path) => readFileSync(join(ROOT, path));

/**
 * Where each file of this repository is served on the site: the page as
 * index.html at the root, the page's other files beside it, and the
 * library's modules under src/, so that every import resolves to a served
 * file with no change to any line.
 * @param {string} path a path in this repository
 * @returns {string} the path on the site
 */
export function servedAt(path) {
  if (path === 'page/sign.html') return 'index.html';
  if (path.startsWith('page/')) return path.slice('page/'.length);
  if (path.startsWith('src/')) return path;
  throw new Error(`no place on the site for ${path}`);
}

/**
 * The files copied from this repository: each by its path on the site and
 * its path here. The page, its style sheet, and every module the page's
 * script imports, found through the imports as the single-file checking
 * page finds its own.
 * @returns {Record<string, string>} site path to repository path
 */
export function copiedFiles() {
  const files = { 'index.html': 'page/sign.html', 'style.css': 'page/style.css' };
  for (const [path] of pageModules(START)) files[servedAt(path)] = path;
  return files;
}

// The four actions the publishing workflow uses, pinned to the exact commits
// that this repository's own workflow pins them to, read from it, so that
// the two cannot drift apart.
function pinnedActions() {
  const own = readFileSync(join(ROOT, '.github', 'workflows', 'pages.yml'), 'utf8');
  const pins = {};
  for (const name of ['checkout', 'configure-pages', 'upload-pages-artifact', 'deploy-pages']) {
    const m = own.match(new RegExp(`uses: actions/${name}@([0-9a-f]{40}) # (v[0-9.]+)`));
    if (!m) throw new Error(`.github/workflows/pages.yml does not pin actions/${name} to a commit`);
    pins[name] = `actions/${name}@${m[1]} # ${m[2]}`;
  }
  return pins;
}

/**
 * The files the site needs of its own, by their path in the repository
 * provared/sign: the name it is served at, the workflow that publishes it,
 * a README and the licences.
 * @returns {Record<string, string|Buffer>}
 */
export function ownFiles() {
  const pins = pinnedActions();
  const workflow = `# Publishes ${SITE_NAME} with GitHub Pages: the signing page of Provared, and
# nothing else. The files in site/ are copied as they are; nothing is built.
# They are written by tools/make-sign-site.mjs in the repository
# provared/provared, byte for byte from its page/ and src/, and that tool
# can check this copy against them (node tools/make-sign-site.mjs <this
# folder> --check).
#
# The actions are GitHub's own, each pinned to the exact commit of a
# released version (the comment gives the version), the same commits that
# the repository provared/provared pins, so that a later change to a tag
# cannot change what runs here.

name: Publish ${SITE_NAME}

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ${pins.checkout}
      - name: Gather the site
        run: |
          mkdir -p _site
          cp -r site/. _site/
          touch _site/.nojekyll
          find _site -type f | sort
      - uses: ${pins['configure-pages']}
      - uses: ${pins['upload-pages-artifact']}
        with:
          path: _site

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: ${pins['deploy-pages']}
`;
  const readme = `# The signing page of Provared, at ${SITE_NAME}

This repository publishes one page, https://${SITE_NAME}/, with GitHub
Pages: the page on which a person signs a Provared permission (a slip)
with a passkey, and cancels one. It serves nothing else, on purpose.

## Why a site of its own

A passkey belongs to the website name it was made for (its relying party),
and the browser lets any page under that name ask it to sign. What a passkey
signs is a short value, a fingerprint, which the person cannot read on the
device's prompt. So if the signing page were served under a name that
serves other pages too, any of those pages, or a script running on one,
could have the passkey sign a permission it wrote, by presenting the
permission's fingerprint as an ordinary sign-in challenge. A passkey made
at ${SITE_NAME} can be asked to sign only by a page under ${SITE_NAME},
and nothing but the signing page is served there. Whoever checks a record
can name this address as the one a permission must have been signed at
(\`provared-check --origin https://${SITE_NAME}\`).

This closes one thing and not everything: whoever can serve a page under
this name (the host of the site, or whoever holds the domain name) could
still serve another page here; and a reader who names no address when
checking is protected only by which passkey they trust. The format
description (section 4.4) and the list of threats (section 3) in the main
repository say more.

## What is here

Every file in \`site/\` is a copy, byte for byte, of a file in the main
repository, https://github.com/provared/provared: the page
(\`page/sign.html\`, served as \`index.html\`), its script and the renderer
(\`page/sign-page.js\`, \`page/render.js\`), its style sheet
(\`page/style.css\`), and under \`src/\` only the modules of the library
that the page's script imports. They are written by that repository's
\`tools/make-sign-site.mjs\`, which also checks a copy against the
originals:

\`\`\`
node tools/make-sign-site.mjs <this folder> --check
\`\`\`

\`site/CNAME\` names the address, and \`.github/workflows/pages.yml\`
publishes \`site/\` as it is, with nothing built on the way. The page loads
nothing from anywhere but its own files, sends nothing anywhere, and keeps
nothing about a reader; its content security policy allows only its own
script and style sheet.

Faults and questions: open an issue in the main repository,
https://github.com/provared/provared/issues, or write to hello@prova.red.

## Licences

The code is under the Apache License 2.0 (\`LICENSE\`) and this README under
the Creative Commons Attribution 4.0 licence (\`LICENSE-CC-BY-4.0.txt\`), as
in the main repository. Copyright 2026 Pavel Izmaylov.
`;
  return {
    'site/CNAME': `${SITE_NAME}\n`,
    '.github/workflows/pages.yml': workflow,
    'README.md': readme,
    LICENSE: read('LICENSE'),
    'LICENSE-CC-BY-4.0.txt': read('LICENSE-CC-BY-4.0.txt'),
  };
}

/**
 * Every file of the repository provared/sign, by its path there: the
 * copies under site/, and the site's own files.
 * @returns {Record<string, Buffer|string>}
 */
export function siteFiles() {
  const files = {};
  for (const [served, here] of Object.entries(copiedFiles())) files[posix.join('site', served)] = read(here);
  Object.assign(files, ownFiles());
  return files;
}

// Every file under a folder, by its path with forward slashes, .git left out.
function filesUnder(folder) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(join(folder, dir), { withFileTypes: true })) {
      if (dir === '' && entry.name === '.git') continue;
      const path = dir === '' ? entry.name : `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else out.push(path);
    }
  };
  if (existsSync(folder)) walk('');
  return out.sort();
}

/**
 * Write the site into a folder. The folder may hold a .git folder and files
 * this tool writes; any other file stops the tool, so that it never writes
 * into the wrong place and the site never serves anything else.
 * @param {string} folder
 * @returns {string[]} the paths written
 */
export function writeSite(folder) {
  const files = siteFiles();
  const others = filesUnder(folder).filter((path) => !Object.hasOwn(files, path));
  if (others.length) throw new Error(`${folder} holds files this tool does not write, so nothing was written: ${others.join(', ')}`);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(folder, ...path.split('/').slice(0, -1)), { recursive: true });
    writeFileSync(join(folder, ...path.split('/')), content);
  }
  return Object.keys(files).sort();
}

/**
 * Compare a folder written before with this repository as it stands: every
 * file must be there and equal, byte for byte, and nothing else may be
 * there.
 * @param {string} folder
 * @returns {string[]} what differs, in words; empty where nothing does
 */
export function checkSite(folder) {
  const files = siteFiles();
  const found = filesUnder(folder);
  const differences = [];
  for (const [path, content] of Object.entries(files)) {
    if (!found.includes(path)) {
      differences.push(`missing: ${path}`);
      continue;
    }
    if (!Buffer.from(content).equals(readFileSync(join(folder, ...path.split('/'))))) differences.push(`differs: ${path}`);
  }
  for (const path of found) if (!Object.hasOwn(files, path)) differences.push(`not from this repository: ${path}`);
  return differences;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [folder, flag] = process.argv.slice(2);
  if (!folder || (flag !== undefined && flag !== '--check')) {
    console.error('Usage: node tools/make-sign-site.mjs <folder> [--check]');
    process.exit(2);
  }
  if (flag === '--check') {
    const differences = checkSite(folder);
    for (const d of differences) console.log(d);
    console.log(differences.length ? `${differences.length} difference(s) between ${folder} and this repository.` : `${folder} is this repository's signing page, byte for byte, and nothing else.`);
    process.exit(differences.length ? 1 : 0);
  }
  const written = writeSite(folder);
  for (const path of written) console.log(path);
  console.log(`${written.length} files written to ${folder}. The name served: ${SITE_NAME}.`);
  // Not used below; kept so that a reader sees how a path on disk relates to one on the site.
  void relative;
  void sep;
}
