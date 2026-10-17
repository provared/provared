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
//        [--book <file>] [--kept <file>]... [--out <folder>] [--stamp-service <fingerprint>]...
//
// The book is read from the recorder's folder (~/.provared/claude-code, or
// the folder PROVARED_CLAUDE_CODE_DIR names) unless --book names it. The
// page goes to site/records/ unless --out names another folder; the sitemap
// is updated only for site/records/.
//
// The recorder starts a new book at 90,000 entries, and keeps each book
// before it as book-1.jsonl, book-2.jsonl and so on. The books kept are
// read from the recorder's folder too, unless --book names the book in
// force; then --kept names each kept book, oldest first. The page then
// shows each book with its own check, and copies each beside the page as
// book-<n>.jsonl, with its checker's answer as checker-answer-<n>.txt. A
// number missing below the highest (book-2.jsonl gone where book-1.jsonl and
// book-3.jsonl are there) is pointed out on the page and printed.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const args = process.argv.slice(2);
const values = (name) => args.flatMap((a, i) => (a === name && i + 1 < args.length ? [args[i + 1]] : []));
const value = (name) => values(name)[0];

const issuers = values('--issuer');
const sealer = value('--sealer');
if (issuers.length === 0 || !sealer) {
  console.error('Usage: node tools/make-record-page.mjs --issuer <passkey thumbprint> --sealer <recorder key-set fingerprint> [--book <file>] [--kept <file>]... [--out <folder>] [--stamp-service <fingerprint>]...');
  process.exit(2);
}
const home = process.env.USERPROFILE || process.env.HOME || '.';
const folder = process.env.PROVARED_CLAUDE_CODE_DIR || join(home, '.provared', 'claude-code');
const bookPath = value('--book') || join(folder, 'book.jsonl');
const defaultOut = join(root, 'site', 'records');
const out = value('--out') ? resolve(value('--out')) : defaultOut;
const stampServices = values('--stamp-service');
// The books kept before the one in force, oldest first: those --kept names where --book names the
// book in force, or else the recorder's own, book-<n>.jsonl in its folder, in the order of <n>.
// The rule for a kept book's name is the recorder's own (KEPT_BOOK in
// integrations/claude-code/recorder.mjs): <n> from 1 to 999,999,999, with no
// leading zero. The recorder keeps no book under a name this rule does not read.
const KEPT_BOOK = /^book-([1-9][0-9]{0,8})\.jsonl$/;
const keptPaths = value('--book')
  ? values('--kept')
  : (existsSync(folder) ? readdirSync(folder) : [])
    .flatMap((f) => { const m = KEPT_BOOK.exec(f); return m ? [[Number(m[1]), join(folder, f)]] : []; })
    .sort((a, b) => a[0] - b[0]).map(([, p]) => p);

// The recorder adds lines all the time, so the book is read once, into the page's own folder, and
// everything here is made from that copy: the checker's answer, the counts, the size and the
// fingerprints all describe one book. A last line still being written is left out.
mkdirSync(out, { recursive: true });
function readWhole(path, copy, said) {
  let read = readFileSync(path);
  const whole = read.lastIndexOf(0x0a) + 1;
  if (whole < read.length) {
    console.log(`${said}'s last line was still being written: the page is made from the ${read.subarray(0, whole).toString('utf8').split('\n').length - 1} whole lines before it.`);
    read = read.subarray(0, whole);
  }
  writeFileSync(copy, read);
  return read;
}
const copied = join(out, 'book.jsonl');
const bytes = readWhole(bookPath, copied, 'The book');

function check(file, extra) {
  const checkerArgs = [join(root, 'bin', 'provared-check.mjs'), file, ...issuers.flatMap((i) => ['--issuer', i]), '--sealer', sealer];
  for (const s of stampServices) checkerArgs.push('--stamp-service', s);
  const r = spawnSync(process.execPath, [...checkerArgs, ...extra], { encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.error) throw r.error;
  if (r.status === 2) throw new Error(`the checker refused the book (code 2):\n${r.stdout}${r.stderr}`);
  return r.stdout;
}

const text = check(copied, []);
const result = JSON.parse(check(copied, ['--json']));
const book = bytes.toString('utf8');
if (result.entries[0]?.kind !== 'slip') throw new Error('the first entry of the book is not a slip');
// Each kept book, copied beside the page as book-<n>.jsonl and checked on its own, as the book in force is.
// A kept book keeps the recorder's own number (book-<n>.jsonl), so that the names on the page are the
// recorder's; where the files handed over are not all so named, with numbers that differ, they are
// numbered 1, 2, 3 in the order given.
const ownNumbers = keptPaths.map((p) => { const m = KEPT_BOOK.exec(basename(p)); return m ? Number(m[1]) : null; });
const useOwn = ownNumbers.every((n) => n !== null) && new Set(ownNumbers).size === ownNumbers.length;
const kept = keptPaths.map((path, i) => {
  const n = useOwn ? ownNumbers[i] : i + 1;
  const file = `book-${n}.jsonl`;
  const keptBytes = readWhole(path, join(out, file), `Kept book ${n}`);
  const keptText = check(join(out, file), []);
  const keptResult = JSON.parse(check(join(out, file), ['--json']));
  if (keptResult.entries[0]?.kind !== 'slip') throw new Error(`the first entry of kept book ${n} is not a slip`);
  return { n, file, answer: `checker-answer-${n}.txt`, bytes: keptBytes, text: keptText, result: keptResult, lines: keptBytes.toString('utf8').split('\n') };
});
const books = [...kept, { n: 0, file: 'book.jsonl', answer: 'checker-answer.txt', bytes, text, result, lines: book.split('\n') }];
const several = kept.length > 0;
// The recorder numbers its kept books 1, 2, 3 in order, after the highest there, never in a gap, so
// a number missing below the highest is pointed out. Only the fact is stated: the page cannot tell
// a book the recorder kept and that has gone since from a file put in the folder by hand.
// The numbers missing are found as runs between the numbers there, so that a book numbered in the
// millions costs nothing; a run of three or more is written "a to b", and the files are named
// where ten or fewer are missing.
const missingRuns = [];
if (useOwn && several) {
  let after = 0;
  for (const n of [...ownNumbers].sort((a, b) => a - b)) {
    if (n > after + 1) missingRuns.push([after + 1, n - 1]);
    after = n;
  }
}
const missingCount = missingRuns.reduce((s, [a, b]) => s + b - a + 1, 0);
const missingParts = missingRuns.flatMap(([a, b]) => (b - a >= 2 ? [`${a} to ${b}`] : b > a ? [`${a}`, `${b}`] : [`${a}`]));
const missingWhere = value('--book') ? 'among the books this page was made from' : 'in the recorder\'s folder';
const missingFiles = missingCount <= 10 ? ` (${missingRuns.flatMap(([a, b]) => Array.from({ length: b - a + 1 }, (_, i) => `book-${a + i}.jsonl`)).join(', ')})` : '';
const missingLine = missingCount === 0 ? '' : missingCount === 1
  ? `Book ${missingParts[0]}${missingFiles} is not ${missingWhere}.`
  : `Books ${missingParts.length === 1 ? missingParts[0] : `${missingParts.slice(0, -1).join(', ')} and ${missingParts.at(-1)}`}${missingFiles} are not ${missingWhere}.`;
if (missingLine) console.log(missingLine);
// Each permission in the books: the first, and one more for each renewal. A new book begins with
// the permission in force, which is shown once, from the first book that holds it.
const slipsAll = [];
for (const b of books) {
  for (const e of b.result.entries.filter((x) => x.kind === 'slip')) if (!slipsAll.some((s) => s.e.fingerprint === e.fingerprint)) slipsAll.push({ e, b });
}
const slips = slipsAll.map((s) => s.e);
const slip = slips[0];
const latest = slips.at(-1);
// The passkeys that signed the book's permissions, by their thumbprints, as the checker gives them.
const signers = [...new Set(slips.map((e) => e.issuerKey))];
const unused = issuers.filter((i) => !signers.includes(i));
if (unused.length > 0) {
  console.error(`--issuer names a passkey that signed no permission in the book: ${unused.join(', ')}`);
  process.exit(2);
}
const stubs = books.flatMap((b) => b.result.entries.filter((e) => e.kind === 'stub'));
const seals = books.flatMap((b) => b.result.entries.filter((e) => e.kind === 'seal').map((e) => ({ e, b })));

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const blockIn = (answer, re) => { const m = answer.match(re); if (!m) throw new Error(`the checker's answer has no block matching ${re}`); return m[0].trimEnd(); };
const block = (re) => blockIn(text, re);
const slipBlock = slipsAll.map(({ e, b }) => blockIn(b.text, new RegExp(`^Entry ${e.index}: SLIP[^\\n]*\\n(?:[^\\n]+\\n)*`, 'm'))).join('\n\n');
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
const breachList = books.flatMap((b) => b.result.entries.filter((e) => e.breaches && e.breaches.length > 0).map((e) => ({ e, b })));
const breaches = breachList.map((x) => x.e);
const first = stubs[0]?.content.when;
const last = stubs.at(-1)?.content.when;
const when = (iso) => (iso ? iso.replace('T', ' ').replace(/:\d\dZ$/, ' UTC') : '');
const now = new Date().toISOString().replace('T', ' ').replace(/:\d\d\.\d+Z$/, ' UTC');
const kb = Math.round(bytes.length / 1024);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
// Where the record is in several books, an entry is named with its book.
const ofBook = (b) => (several ? ` of ${b.file}` : '');

const dayRows = [...byDay.entries()].map(([day, d]) => {
  const parts = sortedCounts(d.actions).map(([a, n]) => `${esc(a)} ${n}`).join(', ');
  return `    <tr><td>${esc(day)}</td><td>${d.total}</td><td>${parts}</td></tr>`;
}).join('\n');
const actionRows = sortedCounts(byAction).map(([a, n]) => `    <tr><td><code>${esc(a)}</code></td><td>${n}</td></tr>`).join('\n');
const toolRows = sortedCounts(byTool).map(([t, n]) => `    <tr><td>${esc(t)}</td><td>${n}</td></tr>`).join('\n');
const sealRows = seals.map(({ e: s, b }) => {
  const stamped = s.stamps && s.stamps.length > 0 ? `${s.stamps.length} outside time-stamp(s)` : 'no outside time-stamp: the time is the recorder\'s own word';
  return `    <tr><td>entry ${s.index}${ofBook(b)}</td><td>the first ${s.content.size} entries</td><td>${esc(when(s.content.when))}</td><td>${esc(stamped)}</td></tr>`;
}).join('\n');

let outside;
if (breaches.length === 0) {
  outside = `<p>The checker finds no action outside the permission, as far as this record shows. A call that the check before acting refused does not run and leaves no entry here, so the record shows what was taken, not what was refused.</p>`;
} else {
  const items = breachList.map(({ e, b }) => `    <li>Entry ${e.index}${ofBook(b)}, ${esc(e.content?.when || '')}, ${esc(e.content?.action || e.kind)}: ${e.breaches.map((x) => `${x.code ? `[${esc(x.code)}] ` : ''}${esc(x.message)}`).join(' ')}</li>`).join('\n');
  outside = `<p>The checker reports ${plural(breaches.length, 'entry', 'entries')} outside the permission. Going outside is not a fault in the record: it is what a sound record shows.</p>\n<ul>\n${items}\n</ul>`;
}
const limits = (result.summary.limits || []).map((l) => `  <li>${esc(l)}</li>`).join('\n');
const validUntil = latest.content.validUntil;
// What a renewal kept: the same actions, limits, conditions, rules and services.
const terms = (e) => JSON.stringify(['actions', 'limits', 'requires', 'never', 'with', 'passes'].map((k) => e.content[k] ?? null));
const renewals = slips.slice(1).map((e, i) => ` It was renewed with permission ${i + 2}, in force from ${esc(when(e.content.validFrom))} until ${esc(when(e.content.validUntil))}, ${terms(e) === terms(slips[i]) ? 'with the same actions, limits and rules' : 'with changes that its entry below shows'}.`).join('');
const slipFiles = slips.map((e, i) => (i === 0 ? 'slip.json' : `slip-${i + 1}.json`));
// Notes of this record's own, each shown only where the book holds what it explains. What the
// record shows is said as fact; what only the author can say is said as the author's account.
const overHourNote = breaches.some((e) => e.index === 3135 && e.content?.when === '2026-10-13T19:28:46Z')
  ? `\n<p>The entry of 13 October 2026, explained: it is the 601st run of a command in one hour, where the permission allows 600. The author states that several helper agents were working at once. Each call is checked against the book as it stands when the call is asked, so calls asked at nearly the same moment near the limit are each allowed, because none of them is in the book yet, and together they can go over. The check before acting does not count calls allowed and not yet recorded; the checker reports what happened, as it should.</p>`
  : '';
const secondPasskeyNote = signers.includes('Wt7n9Omj4ZvioJdUV4OhP2V0pAte3HAVpI0xqL_1aIw') && signers.length > 1
  ? `\n<p>The permission of 14 October 2026 is signed with a different passkey from the first. The author states it is their own, made in another browser. The recorder takes a permission from a passkey it does not already trust only when told to with <code>--new-passkey</code>, and a checker names every passkey it trusts, as the command under "Check it yourself" does.</p>`
  : '';
const slipLinks = slipFiles.map((f) => `<a href="${f}">${f}</a>`).join(', ');
const totalEntries = books.reduce((n, b) => n + b.result.size, 0);
const madeFrom = several ? `${kept.length + 1} books of ${totalEntries} entries in all (the book in force holds ${result.size})` : `a book of ${result.size} entries`;
const command = (file) => `npx provared-check ${file} ${issuers.map((i) => `--issuer ${esc(i)}`).join(' ')} --sealer ${esc(sealer)}`;
// Shown only where the record is in several books.
const booksSection = !several ? '' : `

<h2>The books</h2>
<p>A book holds at most 100,000 entries, so the recorder seals a book at 90,000 entries (or at 100 MB of text, whichever comes first), keeps it, and starts a new one that begins with the permission in force. This record is in ${kept.length + 1} books, each checked on its own; the summary above is the checker's answer for the book in force, <a href="book.jsonl">book.jsonl</a>.</p>
<p>The recorder enforces every limit across its books: it keeps the time and amount of every receipt in the books kept before, and its check before acting counts them, so a new book starts no limit again. A checker given one book counts within that book only, so around the start of a new book the record a checker is shown can hold, across two books, up to twice a limit within one period, though the agent was held to the limit; a total for the whole permission is split between the books. To see the whole, check every book, and add up the receipts of the last of one book and the first of the next.</p>
<p>A kept book moved, renamed or removed while the recorder is stopped is no longer counted by it, and nothing in the record shows that. The recorder numbers its kept books 1, 2, 3 in order, so this page points out a gap in the numbers; it cannot show a missing last one, nor tell a book that has gone from a file put in the folder by hand.</p>${missingLine ? `\n<p>${esc(missingLine)}</p>` : ''}
<table>
  <thead><tr><th>Book</th><th>Entries</th><th>Receipts</th><th>From</th><th>To</th></tr></thead>
  <tbody>
${books.map((b) => { const own = b.result.entries.filter((e) => e.kind === 'stub'); return `    <tr><td><a href="${b.file}">${b.file}</a></td><td>${b.result.size}</td><td>${own.length}</td><td>${esc(when(own[0]?.content.when))}</td><td>${esc(when(own.at(-1)?.content.when))}</td></tr>`; }).join('\n')}
  </tbody>
</table>
${kept.map((k) => `<p>The checker's summary for ${k.file} (${k.result.size} entries, about ${Math.round(k.bytes.length / 1024)} KB), exactly as printed; the whole answer is <a href="${k.answer}">${k.answer}</a>.</p>\n<pre>${esc(blockIn(k.text, /^Summary\n(?:[^\n]+\n)*/m))}</pre>`).join('\n')}
<p>Each kept book is checked as the book in force is, naming the same keys:</p>
<pre>${kept.map((k) => command(k.file)).join('\n')}</pre>`;

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
<link rel="stylesheet" href="../style.css?v=4">
</head>
<body>
<header>
  <p class="small"><a href="../"><svg class="mark" viewBox="0 0 64 64" width="20" height="20" aria-hidden="true"><circle cx="32" cy="32" r="32" fill="#8f000f"/><path d="M20 15 H37 L45 23 V49 H20 Z" fill="#ffffff"/><path d="M37 15 V23 H45" fill="none" stroke="#8f000f" stroke-width="2.5" stroke-linejoin="round"/><path d="M25 29 H40 M25 35 H36" stroke="#8f000f" stroke-width="2.5" stroke-linecap="round"/><path d="M24.5 43 C27 39, 29 46, 31.5 42.5 C34 39, 36 46, 40.5 41.5" fill="none" stroke="#8f000f" stroke-width="3" stroke-linecap="round"/></svg>Provared</a></p>
  <h1>A real record: the coding agent that builds Provared</h1>
  <p class="motto">A real record, for anyone who wants to see one. Evidence, not a verdict.</p>
</header>
<main>

<p>Everything else on this site is an invented example. This page is a real record, kept day by day: the coding agent the author runs to build Provared, recorded under ${slips.length === 1 ? 'a permission' : 'permissions'} the author signed with their own passkey. The record is added to each day until the ${slips.length === 1 ? 'permission' : 'latest permission'} ends on ${esc(when(validUntil))}. This page was last made on ${esc(now)}, from ${madeFrom}.</p>

<h2>What the agent is for</h2>
<p>The agent is Claude Code, a coding agent, which the author uses in their own time to read and change the code of Provared in its repository, run its tests and tools, and publish what the author approves. The permission names it, allows seven kinds of action with limits on four of them, states five rules of conduct, and was signed on 10 October 2026 at <a href="../sign/">prova.red/sign/</a> with the author's passkey.${renewals} The author's name in it, "Pavel i", is what the author typed: a name in a record is a label, and only the keys are checked.</p>${secondPasskeyNote}

<h2>How it is recorded</h2>
<p>A small program runs before and after every tool call the agent makes (Claude Code's "hooks"; the code is <a href="https://github.com/provared/provared/tree/main/integrations/claude-code">integrations/claude-code</a> in the repository). Until 14 October 2026 at 19:05 UTC the hooks ran only for the common tools (reading and changing files, commands, the web and helper agents); from then, for every tool but a question to the person, a plan, a list of tasks, a skill or a search for tools, and for calls that failed as well. Before a call, the check before acting asks whether the call is within the permission; a call outside it is refused and does not run. After the call, the agent's side signs a receipt (a stub) with two keys, one of them quantum-safe, naming the kind of action, the tool, the time, and the SHA-256 fingerprint of the call's arguments. The arguments themselves, and the contents of any file, are never in the record. The kind of action is chosen by the hook from the tool's name and, for a command, from its text (a command that removes something counts as a deletion; one that pushes or publishes counts as a release), not by the agent. A recorder on the author's computer keeps the book and seals it at least once a day with three keys; the seals carry no outside time-stamp, so the time of a seal is the recorder's own word, and the checker says so.</p>

<h2>${slips.length === 1 ? 'The permission' : 'The permissions'}, in the checker's words</h2>
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
${outside}${overHourNote}

<h2>The checker's summary, exactly as printed</h2>
<pre>${esc(summaryBlock)}</pre>
<p>The whole answer, one block for each entry, is <a href="checker-answer.txt">checker-answer.txt</a>.</p>${booksSection}

<h2>Check it yourself</h2>
<p>${several ? `The book in force is <a href="book.jsonl">book.jsonl</a> (${result.size} entries, about ${kb} KB); the books kept before it are under "The books" above. The ${slips.length === 1 ? 'permission' : 'permissions'} of all the books, each once, alone ${slips.length === 1 ? 'is' : 'are'} ${slipLinks}.` : `The book is <a href="book.jsonl">book.jsonl</a> (${result.size} entries, about ${kb} KB), and ${slips.length === 1 ? 'its permission alone is' : 'its permissions alone are'} ${slipLinks}.`} A checker trusts nothing it is not told to trust, so name the keys: ${signers.length === 1 ? 'the author\'s passkey, by its thumbprint,' : `the ${['two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'][signers.length - 2] ?? signers.length} passkeys that signed the permissions, each by its thumbprint,`} and the recorder's three keys, by the fingerprint of the set. With Node.js 24.7 or later:</p>
<pre>npm install provared
npx provared-check book.jsonl ${issuers.map((i) => `--issuer ${esc(i)}`).join(' ')} --sealer ${esc(sealer)}</pre>
<p>Or in a browser, on the <a href="../check/">checking page</a>: choose the file, and paste ${signers.length === 1 ? 'the thumbprint' : 'the thumbprints, one to a line,'} into the passkey box and the fingerprint into the recorder box. No browser tried on the author's computer on 13 October 2026 (Chrome 155, Edge 155 and Brave 155) has the third method a seal is signed with (SLH-DSA), so in a browser the page says that the check was not complete and gives no pass; all three check the receipts' quantum-safe signatures (ML-DSA). The command-line checker checks everything.</p>

<h2>What this record does not show</h2>
<p>The checker says this itself, at the end of its answer:</p>
<ul>
${limits}
</ul>
<p>And two things of this record's own. A refused call leaves no entry, so the record does not show how often the agent was stopped. Every receipt is one-sided, because no other party takes part in a tool call, so each shows what the agent's side said.</p>
<p>One gap in this record, stated: on 11 October 2026, seven tool calls of a helper agent were taken and not recorded. The recorder could not replace the book file while another program was reading it, and the hook reported each as "taken and not in the record". The fault and its fix are in the change log; the seven calls stay unrecorded.</p>

</main>
<footer>
  <p><b>About the author.</b> Pavel Izmaylov builds Provared alone, in their own time and under their own name; on GitHub, <a href="https://github.com/sealwright">sealwright</a>. Every email to <a href="mailto:hello@prova.red?subject=Provared">hello@prova.red</a> is read and answered within a few days.</p>
  <p>This page loads nothing from anywhere but its own style sheet and icon, and keeps nothing about you.</p>
</footer>
</body>
</html>
`;

slipsAll.forEach(({ e, b }, i) => writeFileSync(join(out, slipFiles[i]), b.lines[e.index] + '\n'));
writeFileSync(join(out, 'checker-answer.txt'), text);
for (const k of kept) writeFileSync(join(out, k.answer), k.text);
writeFileSync(join(out, 'index.html'), html);
// The book and the checker's answer grow by megabytes a day, so they are kept in a release of the
// repository, not in the repository itself; the site's publishing run fetches them and publishes
// only if each matches its SHA-256 fingerprint here, in the form "sha256sum --check" reads.
const sha256 = (name) => createHash('sha256').update(readFileSync(join(out, name))).digest('hex');
const published = ['book.jsonl', 'checker-answer.txt', ...kept.flatMap((k) => [k.file, k.answer])];
writeFileSync(join(out, 'files.sha256'), published.map((name) => `${sha256(name)}  ${name}\n`).join(''));

if (out === defaultOut) {
  const sitemapPath = join(root, 'site', 'sitemap.xml');
  const sitemap = readFileSync(sitemapPath, 'utf8');
  const line = `  <url><loc>https://prova.red/records/</loc><lastmod>${new Date().toISOString().slice(0, 10)}</lastmod></url>`;
  const updated = /<url><loc>https:\/\/prova\.red\/records\/<\/loc>[^\n]*/.test(sitemap)
    ? sitemap.replace(/  <url><loc>https:\/\/prova\.red\/records\/<\/loc>[^\n]*/, line)
    : sitemap.replace('</urlset>', `${line}\n</urlset>`);
  if (updated !== sitemap) writeFileSync(sitemapPath, updated);
}

console.log(`${out}: index.html, book.jsonl (${result.size} entries), ${slipFiles.join(', ')}, checker-answer.txt, ${kept.map((k) => `${k.file} (${k.result.size} entries), ${k.answer}, `).join('')}files.sha256`);
if (out === defaultOut) {
  console.log(`The ${several ? 'books' : 'book'} and the checker's ${several ? 'answers' : 'answer'} are not committed: upload them to the release "record" just before the page is pushed, then commit the rest of the folder:`);
  console.log(`  gh release upload record ${published.map((name) => `"site/records/${name}"`).join(' ')} --clobber`);
  console.log('  git add site/records site/sitemap.xml');
}
console.log(summaryBlock);
