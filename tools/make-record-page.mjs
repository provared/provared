#!/usr/bin/env node
// Writes the page at prova.red/records/: a real record, kept by the recorder
// beside Claude Code (integrations/claude-code/) while that agent builds
// Provared.
//
// It copies the book and its slip beside the page, runs the command-line
// checker on the book with the keys the reader is told to trust, keeps the
// checker's whole answer as a text file, and writes index.html from what the
// checker answered: the slip in the checker's own words, the counts by day
// and by kind of action, the seals, the summary exactly as printed, and what
// the check does not show. The note at the top of the page is written here,
// in this file. Nothing is sent anywhere.
//
//   node tools/make-record-page.mjs --issuer <passkey thumbprint> --sealer <recorder key-set fingerprint>
//        [--book <file>] [--out <folder>] [--stamp-service <fingerprint>]...
//
// The book is read from the recorder's folder (~/.provared/claude-code, or
// the folder PROVARED_CLAUDE_CODE_DIR names) unless --book names it. The
// page goes to site/records/ unless --out names another folder; the sitemap
// is updated only for site/records/.

import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const args = process.argv.slice(2);
const values = (name) => args.flatMap((a, i) => (a === name && i + 1 < args.length ? [args[i + 1]] : []));
const value = (name) => values(name)[0];

const issuer = value('--issuer');
const sealer = value('--sealer');
if (!issuer || !sealer) {
  console.error('Usage: node tools/make-record-page.mjs --issuer <passkey thumbprint> --sealer <recorder key-set fingerprint> [--book <file>] [--out <folder>] [--stamp-service <fingerprint>]...');
  process.exit(2);
}
const home = process.env.USERPROFILE || process.env.HOME || '.';
const folder = process.env.PROVARED_CLAUDE_CODE_DIR || join(home, '.provared', 'claude-code');
const bookPath = value('--book') || join(folder, 'book.jsonl');
const defaultOut = join(root, 'site', 'records');
const out = value('--out') ? resolve(value('--out')) : defaultOut;
const stampServices = values('--stamp-service');

function check(extra) {
  const checkerArgs = [join(root, 'bin', 'provared-check.mjs'), bookPath, '--issuer', issuer, '--sealer', sealer];
  for (const s of stampServices) checkerArgs.push('--stamp-service', s);
  const r = spawnSync(process.execPath, [...checkerArgs, ...extra], { encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.error) throw r.error;
  if (r.status === 2) throw new Error(`the checker refused the book (code 2):\n${r.stdout}${r.stderr}`);
  return r.stdout;
}

const text = check([]);
const result = JSON.parse(check(['--json']));
const book = readFileSync(bookPath, 'utf8');
const firstLine = book.slice(0, book.indexOf('\n') < 0 ? book.length : book.indexOf('\n'));
if (result.entries[0]?.kind !== 'slip') throw new Error('the first entry of the book is not a slip');
const slip = result.entries[0];
const stubs = result.entries.filter((e) => e.kind === 'stub');
const seals = result.entries.filter((e) => e.kind === 'seal');

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const block = (re) => { const m = text.match(re); if (!m) throw new Error(`the checker's answer has no block matching ${re}`); return m[0].trimEnd(); };
const slipBlock = block(/^Entry 0: SLIP[^\n]*\n(?:[^\n]+\n)*/m);
const summaryBlock = block(/^Summary\n(?:[^\n]+\n)*/m);

const byDay = new Map();
const byAction = new Map();
const byTool = new Map();
for (const s of stubs) {
  const day = s.content.when.slice(0, 10);
  const d = byDay.get(day) || { total: 0, actions: new Map() };
  d.total += 1;
  d.actions.set(s.content.action, (d.actions.get(s.content.action) || 0) + 1);
  byDay.set(day, d);
  byAction.set(s.content.action, (byAction.get(s.content.action) || 0) + 1);
  const tool = s.content.details?.[0]?.name;
  if (tool) byTool.set(tool, (byTool.get(tool) || 0) + 1);
}
const sortedCounts = (m) => [...m.entries()].sort((a, b) => b[1] - a[1]);
const breaches = result.entries.filter((e) => e.breaches && e.breaches.length > 0);
const first = stubs[0]?.content.when;
const last = stubs.at(-1)?.content.when;
const when = (iso) => (iso ? iso.replace('T', ' ').replace(/:\d\dZ$/, ' UTC') : '');
const now = new Date().toISOString().replace('T', ' ').replace(/:\d\d\.\d+Z$/, ' UTC');
const kb = Math.round(statSync(bookPath).size / 1024);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

const dayRows = [...byDay.entries()].map(([day, d]) => {
  const parts = sortedCounts(d.actions).map(([a, n]) => `${esc(a)} ${n}`).join(', ');
  return `    <tr><td>${esc(day)}</td><td>${d.total}</td><td>${parts}</td></tr>`;
}).join('\n');
const actionRows = sortedCounts(byAction).map(([a, n]) => `    <tr><td><code>${esc(a)}</code></td><td>${n}</td></tr>`).join('\n');
const toolRows = sortedCounts(byTool).map(([t, n]) => `    <tr><td>${esc(t)}</td><td>${n}</td></tr>`).join('\n');
const sealRows = seals.map((s) => {
  const stamped = s.stamps && s.stamps.length > 0 ? `${s.stamps.length} outside time-stamp(s)` : 'no outside time-stamp: the time is the recorder\'s own word';
  return `    <tr><td>entry ${s.index}</td><td>the first ${s.content.size} entries</td><td>${esc(when(s.content.when))}</td><td>${esc(stamped)}</td></tr>`;
}).join('\n');

let outside;
if (breaches.length === 0) {
  outside = `<p>The checker finds no action outside the permission, as far as this record shows. A call that the check before acting refused does not run and leaves no entry here, so the record shows what was taken, not what was refused.</p>`;
} else {
  const items = breaches.map((e) => `    <li>Entry ${e.index}, ${esc(e.content?.when || '')}, ${esc(e.content?.action || e.kind)}: ${e.breaches.map((b) => `${b.code ? `[${esc(b.code)}] ` : ''}${esc(b.message)}`).join(' ')}</li>`).join('\n');
  outside = `<p>The checker reports ${plural(breaches.length, 'entry', 'entries')} outside the permission. Going outside is not a fault in the record: it is what a sound record shows.</p>\n<ul>\n${items}\n</ul>`;
}
const limits = (result.summary.limits || []).map((l) => `  <li>${esc(l)}</li>`).join('\n');
const validUntil = slip.content.validUntil;

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'">
<title>A real record: the coding agent that builds Provared</title>
<meta name="description" content="A real Provared record, kept day by day: the coding agent the author runs to build Provared, under a permission signed with the author's own passkey, with the checker's answer and the files to check it yourself.">
<link rel="canonical" href="https://prova.red/records/">
<link rel="icon" href="../favicon.svg" type="image/svg+xml">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Provared">
<meta property="og:title" content="A real record: the coding agent that builds Provared">
<meta property="og:description" content="Kept day by day under a permission the author signed with a passkey. The checker's answer, and the files to check it yourself.">
<meta property="og:url" content="https://prova.red/records/">
<meta property="og:image" content="https://prova.red/preview.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="A real record: the coding agent that builds Provared">
<meta name="twitter:description" content="Kept day by day under a permission the author signed with a passkey. The checker's answer, and the files to check it yourself.">
<meta name="twitter:image" content="https://prova.red/preview.png">
<link rel="stylesheet" href="../style.css?v=3">
</head>
<body>
<header>
  <p class="small"><a href="../">Provared</a></p>
  <h1>A real record: the coding agent that builds Provared</h1>
  <p class="motto">A real record, for anyone who wants to see one. Evidence, not a verdict.</p>
</header>
<main>

<p>Everything else on this site is an invented example. This page is a real record, kept day by day: the coding agent the author runs to build Provared, recorded under a permission the author signed with their own passkey. The record is added to each day until the permission ends on ${esc(when(validUntil))}. This page was last made on ${esc(now)}, from a book of ${result.size} entries.</p>

<h2>What the agent is for</h2>
<p>The agent is Claude Code, a coding agent, which the author uses in their own time to read and change the code of Provared in its repository, run its tests and tools, and publish what the author approves. The permission names it, allows seven kinds of action with limits on four of them, states five rules of conduct, and was signed on 10 October 2026 at <a href="../sign/">prova.red/sign/</a> with the author's passkey. The author's name in it, "Pavel i", is what the author typed: a name in a record is a label, and only the keys are checked.</p>

<h2>How it is recorded</h2>
<p>A small program runs before and after every tool call the agent makes (Claude Code's "hooks"; the code is <a href="https://github.com/provared/provared/tree/main/integrations/claude-code">integrations/claude-code</a> in the repository). Before a call, the check before acting asks whether the call is within the permission; a call outside it is refused and does not run. After the call, the agent's side signs a receipt (a stub) with two keys, one of them quantum-safe, naming the kind of action, the tool, the time, and the SHA-256 fingerprint of the call's arguments. The arguments themselves, and the contents of any file, are never in the record. The kind of action is chosen by the hook from the tool's name and, for a command, from its text (a command that removes something counts as a deletion; one that pushes or publishes counts as a release), not by the agent. A recorder on the author's computer keeps the book and seals it at least once a day with three keys; the seals carry no outside time-stamp, so the time of a seal is the recorder's own word, and the checker says so.</p>

<h2>The permission, in the checker's words</h2>
<pre>${esc(slipBlock)}</pre>

<h2>What the agent did</h2>
<p>${plural(stubs.length, 'receipt', 'receipts')}, from ${esc(when(first))} to ${esc(when(last))}, under ${plural(seals.length, 'seal', 'seals')}. Days and times are in UTC.</p>
<table>
  <thead><tr><th>Day</th><th>Receipts</th><th>By kind of action</th></tr></thead>
  <tbody>
${dayRows}
  </tbody>
</table>
<table>
  <thead><tr><th>Kind of action</th><th>Receipts</th></tr></thead>
  <tbody>
${actionRows}
  </tbody>
</table>
<table>
  <thead><tr><th>Tool</th><th>Receipts</th></tr></thead>
  <tbody>
${toolRows}
  </tbody>
</table>
<table>
  <thead><tr><th>Seal</th><th>Covers</th><th>Sealed at</th><th>Time-stamp</th></tr></thead>
  <tbody>
${sealRows}
  </tbody>
</table>

<h2>Where it went outside its permission</h2>
${outside}

<h2>The checker's summary, exactly as printed</h2>
<pre>${esc(summaryBlock)}</pre>
<p>The whole answer, one block for each entry, is <a href="checker-answer.txt">checker-answer.txt</a>.</p>

<h2>Check it yourself</h2>
<p>The book is <a href="book.jsonl">book.jsonl</a> (${result.size} entries, about ${kb} KB), and its permission alone is <a href="slip.json">slip.json</a>. A checker trusts nothing it is not told to trust, so name the two keys: the author's passkey, by its thumbprint, and the recorder's three keys, by the fingerprint of the set. With Node.js 24.7 or later:</p>
<pre>npm install provared
npx provared-check book.jsonl --issuer ${esc(issuer)} --sealer ${esc(sealer)}</pre>
<p>Or in a browser, on the <a href="../check/">checking page</a>: choose the file, and paste the thumbprint into the passkey box and the fingerprint into the recorder box. Where the browser lacks the quantum-safe signing methods, the page says that the check was not complete and gives no pass; the command-line checker checks everything.</p>

<h2>What this record does not show</h2>
<p>The checker says this itself, at the end of its answer:</p>
<ul>
${limits}
</ul>
<p>And two things of this record's own. A refused call leaves no entry, so the record does not show how often the agent was stopped. Every receipt is one-sided, because no other party takes part in a tool call, so each shows what the agent's side said.</p>

</main>
<footer>
  <p><b>About the author.</b> Pavel Izmaylov builds Provared alone, in their own time and under their own name; on GitHub, <a href="https://github.com/sealwright">sealwright</a>. Every email to <a href="mailto:hello@prova.red?subject=Provared">hello@prova.red</a> is read and answered within a few days.</p>
  <p>This page loads nothing from anywhere but its own style sheet and icon, and keeps nothing about you.</p>
</footer>
</body>
</html>
`;

mkdirSync(out, { recursive: true });
copyFileSync(bookPath, join(out, 'book.jsonl'));
writeFileSync(join(out, 'slip.json'), firstLine + '\n');
writeFileSync(join(out, 'checker-answer.txt'), text);
writeFileSync(join(out, 'index.html'), html);

if (out === defaultOut) {
  const sitemapPath = join(root, 'site', 'sitemap.xml');
  const sitemap = readFileSync(sitemapPath, 'utf8');
  const line = `  <url><loc>https://prova.red/records/</loc><lastmod>${new Date().toISOString().slice(0, 10)}</lastmod></url>`;
  const updated = /<url><loc>https:\/\/prova\.red\/records\/<\/loc>[^\n]*/.test(sitemap)
    ? sitemap.replace(/  <url><loc>https:\/\/prova\.red\/records\/<\/loc>[^\n]*/, line)
    : sitemap.replace('</urlset>', `${line}\n</urlset>`);
  if (updated !== sitemap) writeFileSync(sitemapPath, updated);
}

console.log(`${out}: index.html, book.jsonl (${result.size} entries), slip.json, checker-answer.txt`);
console.log(summaryBlock);
