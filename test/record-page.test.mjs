// The tool that writes the page at prova.red/records/ from a real book:
// run here on the sample record, into a folder of its own, so that the
// page, the copied files and the checker's answer are checked without
// touching site/. The note on the page is written for the Claude Code
// record; this test checks only what the tool makes from a book.

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
