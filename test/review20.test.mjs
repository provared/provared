// What the broad final review found, in the package as it is to be
// published (5 October 2026). Each fault is fixed and each is a test here.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { shown } from '../page/render.js';
import { assembleSlip, checkBook, entryLine, keySetFingerprint, prepareSlip, thumbprint, toBase64url } from '../src/index.js';
import { cancelWithPasskey, signChallengeWithPasskey } from '../src/passkey-browser.js';
import { START, makeWorld } from './helpers/world.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'bin', 'provared-check.mjs');

// The installed command is run without any flag, as a person would run it.
function run(...args) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function saved(text) {
  const file = join(mkdtempSync(join(tmpdir(), 'provared-')), 'book.jsonl');
  writeFileSync(file, text);
  return file;
}

test('finding 1: exit code 0 needs the passkey you trust and, for a sealed book, the recorder you expect', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  const issuer = await thumbprint(w.passkey.key);
  const plain = saved(w.book());
  const none = run(plain);
  assert.equal(none.code, 1);
  assert.match(none.out, /Checked against keys you named\?\s+NO: you named no passkey you trust/);
  assert.equal(run(plain, '--issuer', issuer).code, 0);

  await w.seal();
  const sealedBook = saved(w.book());
  const noSealer = run(sealedBook, '--issuer', issuer);
  assert.equal(noSealer.code, 1);
  assert.match(noSealer.out, /the record has a seal, and you named no recorder you expect/);
  const both = run(sealedBook, '--issuer', issuer, '--sealer', await keySetFingerprint(w.recorder.keys));
  assert.equal(both.code, 0);
  assert.match(both.out, /yes: the passkey you trust, and the recorder you expect/);
  // The installed command does not repeat the platform's warning that its methods are experimental.
  assert.doesNotMatch(both.err, /ExperimentalWarning/);
});

test('finding 6: a trust value that is not a fingerprint is refused, never set aside', async () => {
  const w = await makeWorld();
  const file = saved(w.book());
  const issuer = await thumbprint(w.passkey.key);
  for (const option of ['--issuer', '--sealer', '--stamp-service', '--voucher', '--root']) {
    for (const value of ['abc', issuer + ' ', issuer.slice(1)]) {
      const r = run(file, option, value);
      assert.equal(r.code, 2, `${option} ${JSON.stringify(value)}`);
      assert.match(r.err, /is not a fingerprint/);
    }
  }
  assert.equal(run(file, '--block', 'xyz').code, 2);
  // An option that may be given once is refused when given twice.
  const r = run(file, '--root', issuer, '--root', issuer);
  assert.equal(r.code, 2);
  assert.match(r.err, /--root may be given once/);
  // Asking for help is not a failure.
  const help = run('--help');
  assert.equal(help.code, 0);
  assert.match(help.out, /Usage: provared-check/);
});

test('finding 4: a long run of marks drawn on a letter is kept to three, on the page and in the terminal', async () => {
  const stacked = 'a' + '́'.repeat(999);
  assert.equal(shown(stacked), 'á́́�');
  // Accents as ordinary text uses them are left as they are.
  assert.equal(shown('Zé'), 'Zé');
  const w = await makeWorld({ fields: { purpose: stacked } });
  const r = run(saved(w.book()), '--issuer', await thumbprint(w.passkey.key));
  assert.ok(!/\p{M}{4}/u.test(r.out), 'no run of more than three marks');
  assert.match(r.out, /Purpose:\s+"á́́�"/);
  const json = run(saved(w.book()), '--issuer', await thumbprint(w.passkey.key), '--json');
  assert.ok(!/\p{M}{4}/u.test(json.out), 'none in --json either');
  assert.ok(JSON.stringify(JSON.parse(json.out)).includes(stacked), 'the JSON is still exact');
});

test('finding 7: stubs whose slip fails are counted as neither countersigned nor one-sided', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  await w.add({ when: START + 2 * 3600 * 1000 });
  await w.add({ when: START + 3 * 3600 * 1000, countersigned: false });
  const good = await checkBook(w.book());
  assert.equal(good.summary.counts.countersigned, 2);
  assert.equal(good.summary.counts.oneSided, 1);
  // The slip's passkey signature damaged.
  const [first, ...rest] = w.book().trimEnd().split('\n');
  const slip = JSON.parse(first);
  const sig = slip.slip.signatures[0].signature;
  slip.slip.signatures[0].signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  const broken = await checkBook([entryLine(slip), ...rest].join('\n') + '\n');
  assert.equal(broken.summary.problemFound, true);
  assert.equal(broken.summary.counts.countersigned, 0);
  assert.equal(broken.summary.counts.oneSided, 1);
});

test('finding 10: a carriage return before each line feed, a byte-order mark and an empty line are named as such', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  const book = w.book();
  const cases = [
    [book.replaceAll('\n', '\r\n'), 'line-not-canonical', /carriage return/],
    ['﻿' + book, 'not-json', /byte-order mark/],
    [book + '\n', 'not-json', /The line is empty/],
  ];
  for (const [text, code, words] of cases) {
    const r = await checkBook(text);
    const problems = r.entries.flatMap((e) => e.problems);
    assert.ok(problems.some((p) => p.code === code && words.test(p.message)), String(words));
  }
});

// The browser's passkey interface, stood in for by the tests' software passkey.
function inBrowser(passkey, body) {
  const names = ['isSecureContext', 'navigator', 'PublicKeyCredential'];
  const before = names.map((name) => Object.getOwnPropertyDescriptor(globalThis, name));
  const define = (name, value) => Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  define('isSecureContext', true);
  define('PublicKeyCredential', function PublicKeyCredential() {});
  define('navigator', { credentials: { get: async ({ publicKey }) => ({ response: await passkey.sign(publicKey.challenge) }) } });
  return body().finally(() => {
    names.forEach((name, i) => {
      if (before[i]) Object.defineProperty(globalThis, name, before[i]);
      else delete globalThis[name];
    });
  });
}

test('finding 8: in a browser, a slip can be cancelled with its passkey, and a slip with covered fields signed', async () => {
  const w = await makeWorld();
  await w.add({ when: START + 3600 * 1000 });
  const stored = { credentialId: toBase64url(new Uint8Array(16)), key: w.passkey.key, rpId: w.passkey.rpId, origin: w.passkey.origin };
  const issuerKeys = [await thumbprint(w.passkey.key)];

  const cancellation = await inBrowser(w.passkey, () => cancelWithPasskey({ slip: w.slipFingerprint, when: START + 2 * 3600 * 1000 }, stored));
  const r = await checkBook(w.book() + entryLine({ cancellation }) + '\n', { issuerKeys });
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.summary.counts.cancellations, 1);
  assert.equal(r.entries.at(-1).signature.state, 'valid');

  const prepared = await prepareSlip({ ...w.fields, validFrom: '2026-10-06T08:00:00Z' }, { cover: ['purpose'] });
  const slip = assembleSlip(prepared, await inBrowser(w.passkey, () => signChallengeWithPasskey(prepared.challenge, stored)));
  const covered = await checkBook(entryLine({ slip }) + '\n', { issuerKeys });
  assert.equal(covered.summary.problemFound, false);
  assert.equal(covered.entries[0].covered.length, 1);
  assert.equal(readFileSync(join(root, 'src', 'passkey-browser.d.ts'), 'utf8').includes('cancelWithPasskey'), true);
});
