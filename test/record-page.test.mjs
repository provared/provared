// The tool that writes the page at prova.red/records/ from a real book:
// run here on the sample record, into a folder of its own, so that the
// page, the copied files and the checker's answer are checked without
// touching site/. The note on the page is written for the Claude Code
// record; this test checks only what the tool makes from a book.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const root = new URL('..', import.meta.url);
const sample = join(root.pathname.replace(/^\/([A-Za-z]:)/, '$1'), 'samples', 'office-supplies.jsonl');
const expected = JSON.parse(readFileSync(new URL('../samples/office-supplies.expected.json', import.meta.url), 'utf8'));
const tool = new URL('../tools/make-record-page.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const sitemap = new URL('../site/sitemap.xml', import.meta.url);

test('the record page is written from the book, with the checker\'s own words, and nothing else of the site is touched', () => {
  const out = mkdtempSync(join(tmpdir(), 'provared-record-page-'));
  const sitemapBefore = readFileSync(sitemap, 'utf8');
  try {
    const r = spawnSync(process.execPath, [tool, '--book', sample, '--issuer', expected.issuerKey, '--sealer', expected.sealKeys[0], '--stamp-service', expected.stampServices[0], '--out', out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const page = readFileSync(join(out, 'index.html'), 'utf8');
    assert.ok(page.includes('Entry 0: SLIP'), 'the slip in the checker\'s words');
    assert.ok(page.includes('Did the agent stay within its slip?   NO: first at entry 5'), 'the summary exactly as printed');
    assert.ok(page.includes('Time-stamped in a way you trust?      yes'), 'the named time-stamp service is used');
    assert.ok(page.includes('[over-limit]'), 'the entries outside the slip are listed');
    assert.ok(page.includes(`--issuer ${expected.issuerKey} --sealer ${expected.sealKeys[0]}`), 'the command names the keys to trust');
    assert.ok(!/<script/i.test(page), 'no script on the page');
    assert.ok(page.includes('Content-Security-Policy'), 'the same policy as the other pages');
    assert.equal(readFileSync(join(out, 'book.jsonl'), 'utf8'), readFileSync(sample, 'utf8'), 'the book is copied as it is');
    const firstLine = readFileSync(sample, 'utf8').split('\n')[0];
    assert.equal(readFileSync(join(out, 'slip.json'), 'utf8'), firstLine + '\n', 'the slip is the first line of the book');
    assert.ok(readFileSync(join(out, 'checker-answer.txt'), 'utf8').includes('Summary\n'), 'the whole answer is kept');
    // The book and the answer are published from a release; their fingerprints, in the form sha256sum --check reads, are kept with the page.
    const sha256 = (name) => createHash('sha256').update(readFileSync(join(out, name))).digest('hex');
    assert.equal(readFileSync(join(out, 'files.sha256'), 'utf8'), `${sha256('book.jsonl')}  book.jsonl\n${sha256('checker-answer.txt')}  checker-answer.txt\n`);
    // The two notes written for the Claude Code record appear only where the book holds what they explain.
    assert.ok(!page.includes('The author states'), 'no note of the Claude Code record on another book');
    assert.ok(!page.includes('The entry of 13 October 2026') && !page.includes('The permission of 14 October 2026'));
    assert.equal(readFileSync(sitemap, 'utf8'), sitemapBefore, 'the sitemap is not changed for a folder outside the site');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('the tool refuses to run without the keys to trust', () => {
  const r = spawnSync(process.execPath, [tool, '--book', sample], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.ok(r.stderr.includes('Usage'));
});

test('a renewed permission: the page shows both, the command names each passkey, and each permission has its own file', async () => {
  const { writeBook, thumbprint } = await import('../src/index.js');
  const { keySetFingerprint } = await import('../src/seal.js');
  const { makeWorld } = await import('./helpers/world.mjs');
  const first = await makeWorld();
  await first.add();
  await first.seal();
  const second = await makeWorld({ agent: first.agent, fields: { validFrom: '2026-10-12T08:00:00Z', validUntil: '2026-12-31T23:59:59Z' } });
  await second.add({ when: Date.parse('2026-10-12T09:00:00Z') });
  const out = mkdtempSync(join(tmpdir(), 'provared-record-page-'));
  try {
    const bookPath = join(out, 'source.jsonl');
    const text = writeBook([...first.entries, ...second.entries]);
    writeFileSync(bookPath, text);
    const issuers = [await thumbprint(first.passkey.key), await thumbprint(second.passkey.key)];
    const sealer = await keySetFingerprint(first.recorder.keys);
    const r = spawnSync(process.execPath, [tool, '--book', bookPath, '--issuer', issuers[0], '--issuer', issuers[1], '--sealer', sealer, '--out', join(out, 'page')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const page = readFileSync(join(out, 'page', 'index.html'), 'utf8');
    assert.ok(page.includes('The permissions, in the checker&#39;s words') || page.includes("The permissions, in the checker's words"));
    assert.ok(page.includes('Entry 0: SLIP') && page.includes(`Entry ${first.entries.length}: SLIP`), 'both permissions in the checker\'s words');
    assert.ok(page.includes('renewed with permission 2'), 'the renewal is said');
    assert.ok(page.includes(`--issuer ${issuers[0]} --issuer ${issuers[1]} --sealer ${sealer}`), 'the command names each passkey');
    assert.ok(page.includes('until the latest permission ends on 2026-12-31 23:59 UTC'));
    const lines = text.split('\n');
    assert.equal(readFileSync(join(out, 'page', 'slip.json'), 'utf8'), lines[0] + '\n');
    assert.equal(readFileSync(join(out, 'page', 'slip-2.json'), 'utf8'), lines[first.entries.length] + '\n');
    assert.ok(page.includes('the two passkeys that signed the permissions, each by its thumbprint'), 'the passkeys are counted from the book');
    // A passkey that signed no permission in the book is refused, not counted.
    const stray = spawnSync(process.execPath, [tool, '--book', bookPath, '--issuer', issuers[0], '--issuer', issuers[1], '--issuer', 'A'.repeat(43), '--sealer', sealer, '--out', join(out, 'page-2')], { encoding: 'utf8' });
    assert.equal(stray.status, 2, stray.stdout + stray.stderr);
    assert.match(stray.stderr, /signed no permission in the book/);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('a record in several books: each is copied and checked on its own, the page lists them with the limit counted within one book, and the kept books are found in the recorder\'s folder', async () => {
  const { writeBook, thumbprint } = await import('../src/index.js');
  const { keySetFingerprint } = await import('../src/seal.js');
  const { makeWorld } = await import('./helpers/world.mjs');
  // The book kept: a permission, two receipts and a seal. The book in force: a permission and one receipt.
  const first = await makeWorld();
  await first.add();
  await first.add();
  await first.seal();
  const second = await makeWorld({ agent: first.agent, fields: { validFrom: '2026-10-12T08:00:00Z', validUntil: '2026-12-31T23:59:59Z' } });
  await second.add({ when: Date.parse('2026-10-12T09:00:00Z') });
  const out = mkdtempSync(join(tmpdir(), 'provared-record-page-'));
  try {
    const keptText = writeBook(first.entries);
    const inForce = writeBook(second.entries);
    writeFileSync(join(out, 'kept.jsonl'), keptText);
    writeFileSync(join(out, 'in-force.jsonl'), inForce);
    const issuers = [await thumbprint(first.passkey.key), await thumbprint(second.passkey.key)];
    const sealer = await keySetFingerprint(first.recorder.keys);
    const keys = ['--issuer', issuers[0], '--issuer', issuers[1], '--sealer', sealer];
    const r = spawnSync(process.execPath, [tool, '--book', join(out, 'in-force.jsonl'), '--kept', join(out, 'kept.jsonl'), ...keys, '--out', join(out, 'page')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const page = readFileSync(join(out, 'page', 'index.html'), 'utf8');
    assert.ok(page.includes('<h2>The books</h2>'));
    assert.ok(page.includes('This record is in 2 books, each checked on its own'));
    assert.ok(page.includes('The recorder enforces every limit across its books'), 'the recorder holds the agent across books');
    assert.ok(page.includes('can hold, across two books, up to twice a limit within one period, though the agent was held to the limit'), 'the stated limit of a checker given one book');
    assert.ok(page.includes(`from 2 books of ${first.entries.length + second.entries.length} entries in all (the book in force holds ${second.entries.length})`));
    assert.ok(page.includes('<p>3 receipts,'), 'the receipts of both books are counted');
    assert.ok(page.includes(`npx provared-check book-1.jsonl --issuer ${issuers[0]} --issuer ${issuers[1]} --sealer ${sealer}`), 'the command for the kept book');
    assert.ok(page.includes(`entry ${first.entries.length - 1} of book-1.jsonl`), 'the seal is named with its book');
    assert.equal(readFileSync(join(out, 'page', 'book-1.jsonl'), 'utf8'), keptText, 'the kept book is copied as it is');
    assert.equal(readFileSync(join(out, 'page', 'book.jsonl'), 'utf8'), inForce);
    const keptAnswer = readFileSync(join(out, 'page', 'checker-answer-1.txt'), 'utf8');
    assert.ok(keptAnswer.includes('Summary\n') && keptAnswer.includes('Entry 0: SLIP'), 'the kept book has its own answer');
    assert.ok(page.includes(`The checker's summary for book-1.jsonl (${first.entries.length} entries`) || page.includes(`The checker&#39;s summary for book-1.jsonl (${first.entries.length} entries`));
    // Each permission has its own file, from the book that holds it first.
    assert.equal(readFileSync(join(out, 'page', 'slip.json'), 'utf8'), keptText.split('\n')[0] + '\n');
    assert.equal(readFileSync(join(out, 'page', 'slip-2.json'), 'utf8'), inForce.split('\n')[0] + '\n');
    const sha256 = (name) => createHash('sha256').update(readFileSync(join(out, 'page', name))).digest('hex');
    assert.equal(readFileSync(join(out, 'page', 'files.sha256'), 'utf8'), ['book.jsonl', 'checker-answer.txt', 'book-1.jsonl', 'checker-answer-1.txt'].map((n) => `${sha256(n)}  ${n}\n`).join(''));
    // Read from the recorder's folder, the kept books there are taken, in the order of their numbers.
    const folder = join(out, 'folder');
    mkdirSync(folder);
    writeFileSync(join(folder, 'book.jsonl'), inForce);
    writeFileSync(join(folder, 'book-1.jsonl'), keptText);
    const fromFolder = spawnSync(process.execPath, [tool, ...keys, '--out', join(out, 'page-2')], { encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: folder } });
    assert.equal(fromFolder.status, 0, fromFolder.stdout + fromFolder.stderr);
    const plain = (t) => t.replace(/last made on [0-9: -]+ UTC/, 'last made on <time>');
    assert.equal(plain(readFileSync(join(out, 'page-2', 'index.html'), 'utf8')), plain(page), 'the same page');
    assert.equal(readFileSync(join(out, 'page-2', 'files.sha256'), 'utf8'), readFileSync(join(out, 'page', 'files.sha256'), 'utf8'));
    // "Check it yourself" names the book in force as such.
    assert.ok(page.includes('The book in force is <a href="book.jsonl">book.jsonl</a>'));
    assert.ok(page.includes('of all the books, each once, alone are'));
    // The kept books keep the recorder's own numbers, gaps and all.
    const gaps = join(out, 'gaps');
    mkdirSync(gaps);
    writeFileSync(join(gaps, 'book.jsonl'), inForce);
    writeFileSync(join(gaps, 'book-2.jsonl'), keptText);
    writeFileSync(join(gaps, 'book-5.jsonl'), keptText);
    const withGaps = spawnSync(process.execPath, [tool, ...keys, '--out', join(out, 'page-3')], { encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: gaps } });
    assert.equal(withGaps.status, 0, withGaps.stdout + withGaps.stderr);
    const listed = readFileSync(join(out, 'page-3', 'files.sha256'), 'utf8').split('\n').filter(Boolean).map((l) => l.split('  ')[1]);
    assert.deepEqual(listed, ['book.jsonl', 'checker-answer.txt', 'book-2.jsonl', 'checker-answer-2.txt', 'book-5.jsonl', 'checker-answer-5.txt']);
    assert.ok(readFileSync(join(out, 'page-3', 'index.html'), 'utf8').includes('npx provared-check book-5.jsonl'));
    // Without a gap, no book is said to be missing; the stated limit is there all the same.
    assert.ok(!page.includes('is not in the recorder') && !page.includes('are not in the recorder') && !page.includes('among the books this page was made from'));
    assert.ok(page.includes('A kept book moved, renamed or removed while the recorder is stopped is no longer counted by it, and nothing in the record shows that.'));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('a gap in the numbers of the kept books is pointed out on the page and printed', async () => {
  const { writeBook, thumbprint } = await import('../src/index.js');
  const { keySetFingerprint } = await import('../src/seal.js');
  const { makeWorld } = await import('./helpers/world.mjs');
  const first = await makeWorld();
  await first.add();
  await first.seal();
  const second = await makeWorld({ agent: first.agent, fields: { validFrom: '2026-10-12T08:00:00Z', validUntil: '2026-12-31T23:59:59Z' } });
  await second.add({ when: Date.parse('2026-10-12T09:00:00Z') });
  const out = mkdtempSync(join(tmpdir(), 'provared-record-page-'));
  try {
    const keptText = writeBook(first.entries);
    const inForce = writeBook(second.entries);
    const keys = ['--issuer', await thumbprint(first.passkey.key), '--issuer', await thumbprint(second.passkey.key), '--sealer', await keySetFingerprint(first.recorder.keys)];
    // The recorder's folder holds book-1.jsonl and book-3.jsonl: book 2 has gone.
    const folder = join(out, 'folder');
    mkdirSync(folder);
    writeFileSync(join(folder, 'book.jsonl'), inForce);
    writeFileSync(join(folder, 'book-1.jsonl'), keptText);
    writeFileSync(join(folder, 'book-3.jsonl'), keptText);
    const r = spawnSync(process.execPath, [tool, ...keys, '--out', join(out, 'page')], { encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: folder } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes('Book 2 (book-2.jsonl) is not in the recorder\'s folder.'), 'printed');
    const page = readFileSync(join(out, 'page', 'index.html'), 'utf8');
    assert.ok(page.includes('<p>Book 2 (book-2.jsonl) is not in the recorder\'s folder.</p>'), 'only the fact');
    assert.ok(!page.includes('The recorder kept'), 'the page does not say the recorder kept the missing book');
    // Several missing, below the highest.
    const many = join(out, 'many');
    mkdirSync(many);
    writeFileSync(join(many, 'book.jsonl'), inForce);
    writeFileSync(join(many, 'book-2.jsonl'), keptText);
    writeFileSync(join(many, 'book-5.jsonl'), keptText);
    const r2 = spawnSync(process.execPath, [tool, ...keys, '--out', join(out, 'page-2')], { encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: many } });
    assert.equal(r2.status, 0, r2.stdout + r2.stderr);
    assert.ok(readFileSync(join(out, 'page-2', 'index.html'), 'utf8').includes('<p>Books 1, 3 and 4 (book-1.jsonl, book-3.jsonl, book-4.jsonl) are not in the recorder\'s folder.</p>'));
    // A long run of missing numbers is written as a run, without naming each file. A file put in by
    // hand at the highest number a kept book may have (the reviewer's stray case) is read, and only the
    // fact of the gap is stated.
    const far = join(out, 'far');
    mkdirSync(far);
    writeFileSync(join(far, 'book.jsonl'), inForce);
    writeFileSync(join(far, 'book-1.jsonl'), keptText);
    writeFileSync(join(far, 'book-999999999.jsonl'), keptText);
    const r4 = spawnSync(process.execPath, [tool, ...keys, '--out', join(out, 'page-4')], { encoding: 'utf8', env: { ...process.env, PROVARED_CLAUDE_CODE_DIR: far } });
    assert.equal(r4.status, 0, r4.stdout + r4.stderr);
    assert.ok(r4.stdout.includes('Books 2 to 999999998 are not in the recorder\'s folder.'), r4.stdout);
    const farPage = readFileSync(join(out, 'page-4', 'index.html'), 'utf8');
    assert.ok(farPage.includes('<p>Books 2 to 999999998 are not in the recorder\'s folder.</p>'));
    assert.ok(farPage.includes('<a href="book-999999999.jsonl">book-999999999.jsonl</a>'), 'the book at the highest number is on the page');
    assert.ok(farPage.includes('nor tell a book that has gone from a file put in the folder by hand'));
    // Kept books named on the command line: the gap is pointed out, without saying what became of the book.
    const r3 = spawnSync(process.execPath, [tool, '--book', join(folder, 'book.jsonl'), '--kept', join(folder, 'book-1.jsonl'), '--kept', join(folder, 'book-3.jsonl'), ...keys, '--out', join(out, 'page-3')], { encoding: 'utf8' });
    assert.equal(r3.status, 0, r3.stdout + r3.stderr);
    assert.ok(readFileSync(join(out, 'page-3', 'index.html'), 'utf8').includes('<p>Book 2 (book-2.jsonl) is not among the books this page was made from.</p>'));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('the book is read once, and a last line still being written is left out of the page, the copy and the fingerprints', () => {
  const out = mkdtempSync(join(tmpdir(), 'provared-record-page-'));
  try {
    const source = join(out, 'source.jsonl');
    const whole = readFileSync(sample, 'utf8');
    writeFileSync(source, whole + '{"stub":{"payload":"half a li');
    const r = spawnSync(process.execPath, [tool, '--book', source, '--issuer', expected.issuerKey, '--sealer', expected.sealKeys[0], '--stamp-service', expected.stampServices[0], '--out', join(out, 'page')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /last line was still being written/);
    assert.equal(readFileSync(join(out, 'page', 'book.jsonl'), 'utf8'), whole, 'the copy holds the whole lines only');
    const entries = whole.split('\n').filter(Boolean).length;
    assert.ok(readFileSync(join(out, 'page', 'index.html'), 'utf8').includes(`from a book of ${entries} entries`), 'the page counts the copy');
    const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
    const answer = readFileSync(join(out, 'page', 'checker-answer.txt'));
    assert.equal(readFileSync(join(out, 'page', 'files.sha256'), 'utf8'), `${sha256(Buffer.from(whole, 'utf8'))}  book.jsonl\n${sha256(answer)}  checker-answer.txt\n`, 'the fingerprints are of the whole lines');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('the site publishes the book and the answer only if they match their fingerprints, and the repository does not hold them', () => {
  const workflow = readFileSync(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');
  assert.ok(workflow.includes('gh release download record'), 'the two files are fetched from the release');
  assert.ok(workflow.includes('sha256sum --check --strict files.sha256'), 'each must match its fingerprint');
  assert.ok(!workflow.includes('--ignore-missing'), 'a missing file is a failure');
  assert.ok(workflow.includes(`grep -o 'href="[a-z0-9.-]*\\.\\(json\\|jsonl\\|txt\\)"' index.html`) && workflow.includes('test -f "$f"'), 'every file the page links must be there');
  const ignored = readFileSync(new URL('../.gitignore', import.meta.url), 'utf8').split(/\r?\n/);
  assert.ok(ignored.includes('site/records/book.jsonl') && ignored.includes('site/records/checker-answer.txt'));
});
