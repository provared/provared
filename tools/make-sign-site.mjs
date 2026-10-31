// Writes the files of the signing page's own site, sign.prova.red, which a
// second public repository (provared/sign) publishes with GitHub Pages: the
// signing page and the library files it loads, each copied byte for byte
// from this repository, a list of their fingerprints, and the few files that
// repository needs of its own (the workflow that publishes it, a README and
// the licence).
//
//   node tools/make-sign-site.mjs <folder> --from <tag or commit>
//       write the whole of the repository provared/sign into the folder,
//       which may hold a .git folder and what this tool wrote before,
//       nothing else; "--from" names where the copies come from, as the
//       README and the workflow say it (a tag, such as v0.6.0, where the
//       files are those of a release; otherwise the commit)
//   node tools/make-sign-site.mjs <folder> --from <tag or commit> --check
//       compare a folder written before with this repository as it stands,
//       and fail where anything differs
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
// modules are under src/, every one of them, as prova.red serves them
// beside the checking page. The page's script imports "../src/check.js";
// from an address at the site's root, "../" stays at the root, so that
// import reaches /src/check.js, and nothing in any copied file is changed.
// site/files.sha256 lists each copied file with its SHA-256, in the form
// that "sha256sum --check" reads, and the workflow checks every file
// against it before it publishes.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
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
 * its path here. The page, its script, the renderer, its style sheet, and
 * every module of the library. The modules the page's script imports,
 * found as the single-file checking page finds its own, must all be among
 * them, or the tool stops: a page that imported a file from elsewhere
 * would not load on the site.
 * @returns {Record<string, string>} site path to repository path
 */
export function copiedFiles() {
  const files = { 'index.html': 'page/sign.html', 'sign-page.js': 'page/sign-page.js', 'render.js': 'page/render.js', 'style.css': 'page/style.css' };
  for (const name of readdirSync(join(ROOT, 'src')).filter((n) => n.endsWith('.js')).sort()) files[`src/${name}`] = `src/${name}`;
  for (const [path] of pageModules(START)) {
    const served = servedAt(path);
    if (files[served] !== path) throw new Error(`the signing page loads ${path}, which this tool does not copy to the site`);
  }
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
 * How the README and the workflow name where the copies come from: a tag
 * where "from" looks like one (v0.6.0), otherwise a commit.
 * @param {string} from
 * @returns {{plain: string, marked: string}} "tag v0.6.0", and the same with the name in backticks
 */
export function sourceWords(from) {
  if (typeof from !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(from)) throw new Error('--from names a tag (such as v0.6.0) or a commit: letters, digits, dots, hyphens and underscores only.');
  const kind = /^v[0-9]/.test(from) ? 'tag' : 'commit';
  return { plain: `${kind} ${from}`, marked: `${kind} \`${from}\`` };
}

/**
 * The list of fingerprints, in the form "sha256sum --check" reads: one line
 * for each copied file, by its path from the site's root, in the order of
 * the paths' characters.
 * @param {Record<string, Buffer>} copies site path to content
 * @returns {string}
 */
export function fingerprintList(copies) {
  return Object.keys(copies).sort().map((path) => `${createHash('sha256').update(copies[path]).digest('hex')} *./${path}\n`).join('');
}

/**
 * The files the repository provared/sign needs of its own: the workflow
 * that publishes it, a README and the licence.
 * @param {string} from where the copies come from (see sourceWords)
 * @returns {Record<string, string|Buffer>} by their path in that repository
 */
export function ownFiles(from) {
  const pins = pinnedActions();
  const source = sourceWords(from);
  const workflow = `# Publishes https://${SITE_NAME}: the signing page of Provared and the
# library files it loads, exactly as they are in the folder site/. Each file
# is a copy of the same file at ${source.plain} of provared/provared, and
# site/files.sha256 holds their fingerprints; the run stops if any file
# differs from its fingerprint. Only GitHub's own actions are used, each
# pinned to the commit of a released version, as in provared/provared.

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
      - name: Check every file against its fingerprint
        run: |
          cd site
          sha256sum --check --strict files.sha256
          test "$(find . -type f ! -name files.sha256 | wc -l)" -eq "$(wc -l < files.sha256)" || { echo "site/ holds a file that files.sha256 does not list."; exit 1; }
          touch .nojekyll
      - uses: ${pins['configure-pages']}
      - uses: ${pins['upload-pages-artifact']}
        with:
          path: site

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
  const readme = `# ${SITE_NAME}

This repository publishes one page: the page on which a person signs a
Provared permission (a slip) with a passkey, at https://${SITE_NAME}.

Nothing else is ever served at this address, on purpose. A browser lets a
passkey sign only for the website name it was made for and the addresses
under it. A passkey made here can therefore be used by no other page: not
by https://prova.red, not by the application at https://app.prova.red, and
not by a script that gets onto either of them. If the same passkey could be
used by another page, that page could present a record's fingerprint as an
ordinary sign-in question and have the passkey sign a record the person
never saw. The list of threats of Provared describes this in section 3.

## What is here

- \`site/\`: the signing page (\`index.html\`, \`sign-page.js\`, \`render.js\`,
  \`style.css\`) and the library's modules in \`site/src/\`. Each file is a
  byte-for-byte copy of the same file at ${source.marked} of
  https://github.com/provared/provared (\`page/sign.html\` is served here as
  \`index.html\`). \`site/files.sha256\` holds the SHA-256 fingerprint of each.
- \`.github/workflows/pages.yml\`: checks every file against its
  fingerprint and publishes the folder with GitHub Pages.

The page loads nothing from any other site and keeps nothing on a server.
Its content security policy allows only its own scripts and style sheet.

## What it does not protect against

GitHub serves this site, so GitHub, or anyone who controls this
repository or the address's DNS record, could serve a different page here.
The page shows the permission in words before the passkey is asked, so a
person can read what they sign.

## Licence

Apache License 2.0, as for the code of Provared. Copyright 2026 Pavel
Izmaylov.
`;
  return { '.github/workflows/pages.yml': workflow, 'README.md': readme, LICENSE: read('LICENSE') };
}

/**
 * Every file of the repository provared/sign, by its path there: the
 * copies under site/, their list of fingerprints, and the repository's own
 * files.
 * @param {string} from where the copies come from (see sourceWords)
 * @returns {Record<string, Buffer|string>}
 */
export function siteFiles(from) {
  const copies = {};
  for (const [served, here] of Object.entries(copiedFiles())) copies[served] = read(here);
  const files = {};
  for (const [served, content] of Object.entries(copies)) files[`site/${served}`] = content;
  files['site/files.sha256'] = fingerprintList(copies);
  Object.assign(files, ownFiles(from));
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
 * Write the repository's files into a folder. The folder may hold a .git
 * folder and files this tool writes; any other file stops the tool, so
 * that it never writes into the wrong place and the site never serves
 * anything else.
 * @param {string} folder
 * @param {string} from where the copies come from (see sourceWords)
 * @returns {string[]} the paths written
 */
export function writeSite(folder, from) {
  const files = siteFiles(from);
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
 * @param {string} from where the copies come from (see sourceWords)
 * @returns {string[]} what differs, in words; empty where nothing does
 */
export function checkSite(folder, from) {
  const files = siteFiles(from);
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
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const at = args.indexOf('--from');
  const from = at >= 0 ? args[at + 1] : undefined;
  const rest = args.filter((a, i) => a !== '--check' && a !== '--from' && i !== at + 1);
  const [folder] = rest;
  if (!folder || rest.length !== 1 || from === undefined) {
    console.error('Usage: node tools/make-sign-site.mjs <folder> --from <tag or commit> [--check]');
    process.exit(2);
  }
  if (check) {
    const differences = checkSite(folder, from);
    for (const d of differences) console.log(d);
    console.log(differences.length ? `${differences.length} difference(s) between ${folder} and this repository.` : `${folder} is this repository's signing page, byte for byte, and nothing else.`);
    process.exit(differences.length ? 1 : 0);
  }
  const written = writeSite(folder, from);
  for (const path of written) console.log(path);
  console.log(`${written.length} files written to ${folder}, as copies at ${sourceWords(from).plain}. The name served: ${SITE_NAME}.`);
}
